//! Genuine post-Acquire Read and exact owner activation. Completed permissions
//! are retained as provenance only, never renewed. All new effects obey R.
use super::signing::{FinancialSigningServingV1, SigningServiceLease};
use super::writer_acquire::{ReceivedSigning, AWAITING_ACTIVATE_READ};
use super::*;
use crate::signer_activate_wallet_data::*;
use crate::signer_writer_read_acquire_data::{
    SignerAcquireCommittedV1, SignerAcquirePresentationV1,
};
use std::sync::atomic::AtomicU64;
pub(super) const ACTIVATE_READ_REVIEW: u8 = 48;
pub(super) const ACTIVATE_READ_ADMITTED: u8 = 49;
pub(super) const ACTIVATE_PREPARED: u8 = 50;
pub(super) const ACTIVATE_REVIEW: u8 = 51;
pub(super) const ACTIVATE_ARMED: u8 = 52;
pub(super) const ACTIVATE_READY: u8 = 53;
pub(super) const ACTIVATE_ADMITTED: u8 = 54;
pub(super) const AWAITING_WALLET_PREPARE: u8 = 55;

struct ActivateRead {
    entry: Arc<EntryReviewed>,
    wire: SignerActivateReadPresentationV1,
    original_read: Instant,
    ceiling: Instant,
    last_wall: AtomicU64,
    prepared: AtomicBool,
    acquired_presentation: SignerAcquirePresentationV1,
    writer_deadline: Instant,
    service: ReceivedSigning,
}
impl ActivateRead {
    fn from_bounds(
        entry: Arc<EntryReviewed>,
        wire: SignerActivateReadPresentationV1,
        original_read: Instant,
        acquired_presentation: SignerAcquirePresentationV1,
        writer_deadline: Instant,
        service: ReceivedSigning,
    ) -> Result<Arc<Self>> {
        wire.validate()?;
        if wire.actor != entry.wire.presentation.actor
            || wire.source_ceiling_ms != entry.wire.presentation.source_ceiling_ms
            || !read_links_acquired(&wire, &acquired_presentation, &wire.facts.original.acquired)
        {
            return Err(rejected("Activate Read original actor/source changed"));
        }
        let now = Instant::now();
        let wall = state::wall_ms()?;
        let ceiling = entry
            .clocks
            .restrict_received(PROFILE, wire.read_ceiling_ms, original_read, now)?
            .min(entry.original_source)
            .min(writer_deadline)
            .min(service.deadline)
            .min(wall_ceiling(
                now,
                wall,
                wire.facts.reviewed_at_ms,
                wire.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            entry,
            wire,
            original_read,
            ceiling,
            last_wall: AtomicU64::new(wall),
            prepared: AtomicBool::new(false),
            acquired_presentation,
            writer_deadline,
            service,
        });
        b.check_bounds()?;
        Ok(b)
    }
    fn core(&self) -> &Arc<Core> {
        &self.entry.core
    }
    fn slot(&self) -> usize {
        self.entry.slot()
    }
    fn check_bounds(&self) -> Result<()> {
        self.entry.check_custody()?;
        crate::channel::require_time(self.original_read.min(self.ceiling))?;
        self.service.check()?;
        crate::channel::require_time(self.writer_deadline)?;
        observe_wall(
            &self.last_wall,
            self.wire.facts.reviewed_at_ms,
            self.wire.facts.expires_at_ms,
        )
    }
    fn check(&self) -> Result<()> {
        self.check_bounds()?;
        self.core().check_action_restrictions()
    }
}
impl ActivateRead {
    fn bind_service(&self, data: crate::FinancialSigningServiceV1) -> Result<()> {
        self.service.require_same(&data)
    }
    fn service(&self) -> Result<&ReceivedSigning> {
        Ok(&self.service)
    }
}
struct ActivateReview {
    // Retained provenance only. No completed Activate Read action clock is an
    // ancestor of Activate; only entry custody and this own frozen clock apply.
    read: Arc<ActivateRead>,
    wire: SignerActivatePresentationV1,
    original_activate: Instant,
    ceiling: Instant,
    last_wall: AtomicU64,
}
impl ActivateReview {
    fn from_bounds(
        read: Arc<ActivateRead>,
        wire: SignerActivatePresentationV1,
        original_activate: Instant,
    ) -> Result<Arc<Self>> {
        wire.validate()?;
        if !activate_links_read(&wire, &read.wire) {
            return Err(rejected("Activate replaced retained Activate Read/source"));
        }
        let now = Instant::now();
        let wall = state::wall_ms()?;
        let ceiling = read
            .entry
            .clocks
            .restrict_received(PROFILE, wire.activate_ceiling_ms, original_activate, now)?
            .min(read.entry.original_source)
            .min(read.writer_deadline)
            .min(read.service.deadline)
            .min(wall_ceiling(
                now,
                wall,
                wire.facts.reviewed_at_ms,
                wire.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            read,
            wire,
            original_activate,
            ceiling,
            last_wall: AtomicU64::new(wall),
        });
        b.check_bounds()?;
        Ok(b)
    }
    fn core(&self) -> &Arc<Core> {
        self.read.core()
    }
    fn slot(&self) -> usize {
        self.read.slot()
    }
    fn check_bounds(&self) -> Result<()> {
        self.read.entry.check_custody()?;
        self.read.service()?.check()?;
        crate::channel::require_time(self.read.writer_deadline)?;
        crate::channel::require_time(self.original_activate.min(self.ceiling))?;
        observe_wall(
            &self.last_wall,
            self.wire.facts.reviewed_at_ms,
            self.wire.facts.expires_at_ms,
        )
    }
    fn check(&self) -> Result<()> {
        self.check_bounds()?;
        self.core().check_action_restrictions()
    }
}
fn observe_wall(last: &AtomicU64, start: u64, end: u64) -> Result<()> {
    let wall = state::wall_ms()?;
    let prior = last.fetch_max(wall, Ordering::AcqRel);
    if wall < prior || wall < start || wall >= end {
        return Err(rejected("writer action original wall bound elapsed"));
    }
    Ok(())
}
struct ActivateReady {
    review: Arc<ActivateReview>,
    challenge: String,
    digest: String,
}

pub struct SignerActivateReadTicketV1 {
    binding: Arc<ActivateRead>,
    consumed: bool,
}
impl SignerActivateReadTicketV1 {
    pub fn presentation(&self) -> &SignerActivateReadPresentationV1 {
        &self.binding.wire
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        require_phase(
            self.binding.core(),
            self.binding.slot(),
            ACTIVATE_READ_REVIEW,
        )
    }
}
impl Drop for SignerActivateReadTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerActivateReadOutboundV1 {
    binding: Arc<ActivateRead>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerActivateReadOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
/// Only actual matching original-H receive constructs this one-use Read.
pub struct SignerActivateReadFinalV1 {
    binding: Arc<ActivateRead>,
    consumed: bool,
}
impl SignerActivateReadFinalV1 {
    pub fn presentation(&self) -> &SignerActivateReadPresentationV1 {
        &self.binding.wire
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.entry.original_source
    }
    pub fn original_writer_session_deadline(&self) -> Instant {
        self.binding.writer_deadline
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.original_read
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.service.deadline
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        self.binding.service()?.check()?;
        require_phase(
            self.binding.core(),
            self.binding.slot(),
            ACTIVATE_READ_ADMITTED,
        )
    }
    /// Only after the complete actual source/history/writer/immutable recipe
    /// preparation. Protocol progress is not proof of any of those source facts.
    pub fn finish_read(mut self) -> Result<()> {
        self.check_current()?;
        if !self.binding.prepared.load(Ordering::Acquire) {
            return Err(rejected("Activate Read lacks frozen Activate presentation"));
        }
        self.binding.core().phase.step(
            self.binding.slot(),
            ACTIVATE_READ_ADMITTED,
            ACTIVATE_PREPARED,
        )?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerActivateReadFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerActivateReviewTicketV1 {
    binding: Arc<ActivateReview>,
    consumed: bool,
}
impl SignerActivateReviewTicketV1 {
    pub fn presentation(&self) -> &SignerActivatePresentationV1 {
        &self.binding.wire
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        require_phase(self.binding.core(), self.binding.slot(), ACTIVATE_REVIEW)
    }
}
impl Drop for SignerActivateReviewTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerActivateArmOutboundV1 {
    binding: Arc<ActivateReview>,
    consumed: bool,
}
impl Drop for SignerActivateArmOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerActivateArmV1 {
    binding: Arc<ActivateReview>,
}
impl SignerActivateArmV1 {
    pub fn presentation(&self) -> &SignerActivatePresentationV1 {
        &self.binding.wire
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.read.entry.original_source
    }
    pub fn original_writer_session_deadline(&self) -> Instant {
        self.binding.read.writer_deadline
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.read.service.deadline
    }
    pub fn original_activate_deadline(&self) -> Instant {
        self.binding.original_activate
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        require_phase(self.binding.core(), self.binding.slot(), ACTIVATE_ARMED)
    }
}
pub struct SignerActivateReadyTicketV1 {
    binding: Arc<ActivateReady>,
    consumed: bool,
}
impl SignerActivateReadyTicketV1 {
    pub fn presentation(&self) -> &SignerActivatePresentationV1 {
        &self.binding.review.wire
    }
    pub fn activate_ready_digest(&self) -> &str {
        &self.binding.digest
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.review.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.review.check()?;
        require_phase(
            self.binding.review.core(),
            self.binding.review.slot(),
            ACTIVATE_READY,
        )
    }
}
impl Drop for SignerActivateReadyTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.review.core().phase.revoke();
        }
    }
}
pub struct SignerActivateFinalOutboundV1 {
    binding: Arc<ActivateReady>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerActivateFinalOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.review.core().phase.revoke();
        }
    }
}
/// Only exact original-H receive constructs this grant. The service correlation
/// was fixed by genuine native Serving and cannot mint a service owner here.
pub struct SignerActivateFinalV1 {
    binding: Arc<ActivateReady>,
}
impl SignerActivateFinalV1 {
    pub fn presentation(&self) -> &SignerActivatePresentationV1 {
        &self.binding.review.wire
    }
    pub fn activate_ready_digest(&self) -> &str {
        &self.binding.digest
    }
    pub fn signing_service_digest(&self) -> &str {
        &self.binding.review.read.service.digest
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.review.read.entry.original_source
    }
    pub fn original_writer_session_deadline(&self) -> Instant {
        self.binding.review.read.writer_deadline
    }
    pub fn original_activate_deadline(&self) -> Instant {
        self.binding.review.original_activate
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.review.read.service.deadline
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.review.check()?;
        require_phase(
            self.binding.review.core(),
            self.binding.review.slot(),
            ACTIVATE_ADMITTED,
        )
    }
}
fn require_phase(core: &Core, slot: usize, phase: u8) -> Result<()> {
    if core.phase.phase(slot) != phase {
        return Err(rejected("writer action already consumed or wrong phase"));
    }
    Ok(())
}
#[derive(Default)]
pub(super) struct SActivate {
    offered: bool,
    preparing: bool,
    read: Option<Arc<ActivateRead>>,
    review: Option<Arc<ActivateReview>>,
    display_sent: bool,
    ready: Option<Arc<ActivateReady>>,
    attempted: bool,
    terminal: bool,
    committed: Option<SignerActivateCommittedV1>,
}
#[derive(Default)]
pub(super) struct CActivate {
    read_wire: Option<SignerActivateReadPresentationV1>,
    read: Option<Arc<ActivateRead>>,
    wire: Option<SignerActivatePresentationV1>,
    review: Option<Arc<ActivateReview>>,
    observed_ready: Option<String>,
    ready: Option<Arc<ActivateReady>>,
    terminal: bool,
    committed: Option<SignerActivateCommittedV1>,
}
#[derive(Default)]
pub(super) struct HActivate {
    read: Option<SignerActivateReadPresentationV1>,
    wire: Option<SignerActivatePresentationV1>,
    ready: Option<(String, String)>,
    service: Option<ReceivedSigning>,
    writer_deadline: Option<Instant>,
    read_forwarded: bool,
    display_forwarded: bool,
    terminal: bool,
    committed: Option<SignerActivateCommittedV1>,
}
fn read_links_acquired(
    p: &SignerActivateReadPresentationV1,
    a: &SignerAcquirePresentationV1,
    c: &SignerAcquireCommittedV1,
) -> bool {
    let f = &p.facts.original;
    let old = &a.facts;
    p.actor == a.actor
        && p.source_ceiling_ms == a.source_ceiling_ms
        && &f.acquired == c
        && c.presentation_digest == a.presentation_digest
        && c.recipe_digest == a.recipe_digest
        && f.source_identity_digest == old.source_identity_digest
        && f.terms_digest == old.terms_digest
        && f.continuation_request_json == old.continuation_request_json
        && f.continuation_request_digest == old.continuation_request_digest
        && f.original_host_process_instance == old.original_host_process_instance
        && f.owner_certificate_digest == old.owner_certificate_digest
        && f.owner_disclosure_digest == old.owner_disclosure_digest
        && f.writer_selection_digest == old.writer_selection_digest
        && f.source_expires_at_ms == old.source_expires_at_ms
}
fn activate_links_read(
    p: &SignerActivatePresentationV1,
    r: &SignerActivateReadPresentationV1,
) -> bool {
    p.actor == r.actor
        && p.source_ceiling_ms == r.source_ceiling_ms
        && p.facts.original == r.facts.original
        && p.facts.activate_read_presentation_digest == r.presentation_digest
}
fn activated_matches(
    d: &SignerActivateCommittedV1,
    p: &SignerActivatePresentationV1,
    ready: &str,
    service: &str,
) -> bool {
    d.presentation_digest == p.presentation_digest
        && d.activate_ready_digest == ready
        && d.signing_service_digest == service
        && d.activation_request_digest == p.facts.activation_request_digest
        && d.session_id == p.facts.original.acquired.session_id
        && d.writer_epoch == p.facts.writer_epoch
        && p.facts.expected_head_sequence.checked_add(1) == Some(d.head_sequence)
        && d.head_digest != p.facts.expected_head_digest
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_activate_read(
        &mut self,
        facts: SignerActivateReadFactsV1,
        original_source: Instant,
        original_read: Instant,
    ) -> Result<SignerActivateReadPresentationV1> {
        if std::mem::replace(&mut self.activate.offered, true) {
            self.restrict()?;
            return Err(rejected("Activate Read offer reused"));
        }
        let result = self.offer_activate_read_inner(facts, original_source, original_read);
        if result.is_err() {
            self.restrict()?;
        }
        result
    }
    fn offer_activate_read_inner(
        &mut self,
        facts: SignerActivateReadFactsV1,
        original_source: Instant,
        original_read: Instant,
    ) -> Result<SignerActivateReadPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        if self.cancel_seen || self.failed || self.disposed {
            return Err(rejected("Activate Read after terminal"));
        }
        require_phase(&self.core, self.target.index(), AWAITING_ACTIVATE_READ)?;
        let entry = self
            .entry
            .as_ref()
            .ok_or_else(|| rejected("Activate Read original Entry missing"))?;
        let (acquired, committed, service, writer_deadline) =
            self.writer_acquire.retained_result()?;
        if original_source != entry.original_source {
            return Err(rejected("Activate Read changed original source Instant"));
        }
        require_new_deadline(
            original_read,
            original_source.min(writer_deadline).min(service.deadline),
        )?;
        let mut p = SignerActivateReadPresentationV1 {
            version: 1,
            purpose: ACTIVATE_READ_PURPOSE.into(),
            actor: acquired.actor.clone(),
            facts,
            notice: ACTIVATE_READ_NOTICE.into(),
            read_challenge: state::nonce()?,
            source_ceiling_ms: acquired.source_ceiling_ms,
            read_ceiling_ms: self
                .clocks
                .restrictive_offset(original_read, original_source)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        p.validate()?;
        if !read_links_acquired(&p, acquired, committed) {
            return Err(rejected("Activate Read changed retained Acquire originals"));
        }
        let b = ActivateRead::from_bounds(
            Arc::clone(entry),
            p.clone(),
            original_read,
            acquired.clone(),
            writer_deadline,
            service.retained_restriction(),
        )?;
        b.check()?;
        self.core.phase.step(
            self.target.index(),
            AWAITING_ACTIVATE_READ,
            ACTIVATE_READ_REVIEW,
        )?;
        self.activate.read = Some(b);
        self.send(&Packet::ActivateReadDisplay { data: p.clone() })?;
        Ok(p)
    }
    /// All private preparation remains under the supplied actual live Read.
    /// This freezes data once; it does not authorize an Activate effect.
    pub fn begin_activate_review(
        &mut self,
        read: &SignerActivateReadFinalV1,
        facts: SignerActivateFactsV1,
        original_source: Instant,
        original_activate: Instant,
    ) -> Result<SignerActivatePresentationV1> {
        if std::mem::replace(&mut self.activate.preparing, true) {
            self.restrict()?;
            return Err(rejected("Activate preparation reused"));
        }
        let result = self.begin_activate_inner(read, facts, original_source, original_activate);
        if result.is_err() {
            self.restrict()?;
        }
        result
    }
    fn begin_activate_inner(
        &mut self,
        read: &SignerActivateReadFinalV1,
        facts: SignerActivateFactsV1,
        original_source: Instant,
        original_activate: Instant,
    ) -> Result<SignerActivatePresentationV1> {
        read.check_current()?;
        facts.validate()?;
        let retained = self
            .activate
            .read
            .as_ref()
            .ok_or_else(|| rejected("Activate actual Activate Read missing"))?;
        if !Arc::ptr_eq(&read.binding, retained)
            || self.activate.review.is_some()
            || original_source != retained.entry.original_source
            || self.cancel_seen
            || self.failed
            || self.disposed
            || self.activate.terminal
        {
            return Err(rejected("Activate preparation foreign or reused"));
        }
        require_new_deadline(
            original_activate,
            original_source
                .min(retained.writer_deadline)
                .min(retained.service.deadline),
        )?;
        let mut p = SignerActivatePresentationV1 {
            version: 1,
            purpose: ACTIVATE_PURPOSE.into(),
            actor: retained.wire.actor.clone(),
            recipe_digest: facts.calculate_recipe_digest()?,
            facts,
            notice: ACTIVATE_NOTICE.into(),
            activate_challenge: state::nonce()?,
            source_ceiling_ms: retained.wire.source_ceiling_ms,
            activate_ceiling_ms: self
                .clocks
                .restrictive_offset(original_activate, original_source)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        p.validate()?;
        let binding =
            ActivateReview::from_bounds(Arc::clone(retained), p.clone(), original_activate)?;
        binding.check()?;
        read.check_current()?;
        self.activate.review = Some(binding);
        retained.prepared.store(true, Ordering::Release);
        Ok(p)
    }
    /// Sends only the already frozen complete presentation. No private source
    /// reads or clocks are created after finish_read.
    pub fn send_activate_display(&mut self) -> Result<()> {
        if self.activate.display_sent
            || self.activate.terminal
            || self.cancel_seen
            || self.failed
            || self.disposed
        {
            return Err(rejected("Activate display reused or terminal"));
        }
        let b = self
            .activate
            .review
            .as_ref()
            .ok_or_else(|| rejected("Activate cached presentation missing"))?;
        b.check()?;
        self.core
            .phase
            .step(self.target.index(), ACTIVATE_PREPARED, ACTIVATE_REVIEW)?;
        self.activate.display_sent = true;
        self.send(&Packet::ActivateDisplay {
            data: b.wire.clone(),
        })
    }
    pub fn send_activate_ready(
        &mut self,
        arm: SignerActivateArmV1,
        activate_ready_digest: String,
    ) -> Result<()> {
        let b = self
            .activate
            .review
            .as_ref()
            .ok_or_else(|| rejected("Activate Ready before display"))?;
        if !Arc::ptr_eq(&arm.binding, b)
            || !self.activate.display_sent
            || self.activate.ready.is_some()
            || self.activate.terminal
            || !state::hash(&activate_ready_digest)
        {
            return Err(rejected("Activate Ready foreign or reused"));
        }
        arm.check_current()?;
        let ready = Arc::new(ActivateReady {
            review: Arc::clone(b),
            challenge: state::nonce()?,
            digest: activate_ready_digest,
        });
        self.core
            .phase
            .step(self.target.index(), ACTIVATE_ARMED, ACTIVATE_READY)?;
        self.activate.ready = Some(Arc::clone(&ready));
        self.send(&Packet::ActivateReady {
            actor: b.wire.actor.clone(),
            presentation_digest: b.wire.presentation_digest.clone(),
            recipe_digest: b.wire.recipe_digest.clone(),
            ready_challenge: ready.challenge.clone(),
            activate_ready_digest: ready.digest.clone(),
        })
    }
    pub fn send_activate_read_failed(&mut self) -> Result<()> {
        let read = self
            .activate
            .read
            .as_ref()
            .ok_or_else(|| rejected("Activate Read failure before display"))?;
        if self.activate.terminal || self.activate.display_sent {
            return Err(rejected(
                "Activate Read failure reused or after Activate display",
            ));
        }
        let actor = read.wire.actor.clone();
        let presentation_digest = read.wire.presentation_digest.clone();
        self.activate.terminal = true;
        self.restrict()?;
        self.send(&Packet::ActivateReadFailed {
            actor,
            presentation_digest,
        })
    }
    /// Actual completed-source observation only, never another action grant.
    pub fn report_activated(&mut self, data: SignerActivateCommittedV1) -> Result<()> {
        data.validate()?;
        let r = self
            .activate
            .ready
            .as_ref()
            .ok_or_else(|| rejected("Activate report before Ready"))?;
        let b = &r.review;
        if !self.activate.attempted
            || self.activate.terminal
            || self.activate.committed.is_some()
            || !activated_matches(&data, &b.wire, &r.digest, &b.read.service.digest)
        {
            return Err(rejected("Activate completed-source binding"));
        }
        // Authenticated immutable results survive R and elapsed action clocks.
        // Retention cannot grant another attempt or a Wallet permission.
        self.core
            .phase
            .observe_workflow_activated_saved(self.target.index())?;
        let actor = b.wire.actor.clone();
        self.activate.committed = Some(data.clone());
        self.send(&Packet::Activated { actor, data })
    }
    pub fn send_activate_outcome(&mut self, data: SignerActivateOutcomeV1) -> Result<()> {
        data.validate()?;
        let b = self
            .activate
            .review
            .as_ref()
            .ok_or_else(|| rejected("Activate outcome before preparation"))?;
        if !self.activate.display_sent
            || self.activate.terminal
            || self.activate.committed.is_some()
            || !outcome_matches(
                &b.wire,
                self.activate.ready.as_ref().map(|r| r.digest.as_str()),
                &data,
            )
        {
            return Err(rejected("Activate outcome mismatch"));
        }
        let actor = b.wire.actor.clone();
        self.activate.terminal = true;
        self.restrict()?;
        self.send(&Packet::ActivateOutcome { actor, data })
    }
    pub(super) fn receive_activate(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        if self.cancel_seen || self.failed || self.disposed || self.activate.terminal {
            return Err(rejected("writer command after terminal"));
        }
        match p {
            Packet::ActivateReadFinal {
                actor,
                presentation_digest,
                read_challenge,
                service,
            } => {
                let b = self
                    .activate
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("Activate Read Final before display"))?;
                if actor != b.wire.actor
                    || presentation_digest != b.wire.presentation_digest
                    || read_challenge != b.wire.read_challenge
                {
                    return Err(rejected("Activate Read Final mismatch"));
                }
                b.bind_service(service)?;
                b.check()?;
                self.core.phase.step(
                    self.target.index(),
                    ACTIVATE_READ_REVIEW,
                    ACTIVATE_READ_ADMITTED,
                )?;
                Ok(SignerFinancialWorkflowRequestV1::ActivateRead(
                    SignerActivateReadFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                ))
            }
            Packet::ActivateArm {
                actor,
                presentation_digest,
                recipe_digest,
            } => {
                let b = self
                    .activate
                    .review
                    .as_ref()
                    .ok_or_else(|| rejected("Activate Arm before display"))?;
                if !self.activate.display_sent
                    || actor != b.wire.actor
                    || presentation_digest != b.wire.presentation_digest
                    || recipe_digest != b.wire.recipe_digest
                {
                    return Err(rejected("Activate Arm mismatch"));
                }
                b.check()?;
                self.core
                    .phase
                    .step(self.target.index(), ACTIVATE_REVIEW, ACTIVATE_ARMED)?;
                Ok(SignerFinancialWorkflowRequestV1::ActivateArm(
                    SignerActivateArmV1 {
                        binding: Arc::clone(b),
                    },
                ))
            }
            Packet::ActivateFinal {
                actor,
                presentation_digest,
                recipe_digest,
                ready_challenge,
                activate_ready_digest,
                service,
            } => {
                if std::mem::replace(&mut self.activate.attempted, true) {
                    return Err(rejected("Activate Final reused"));
                }
                let r = self
                    .activate
                    .ready
                    .as_ref()
                    .ok_or_else(|| rejected("Activate Final before Ready"))?;
                let b = &r.review;
                if actor != b.wire.actor
                    || presentation_digest != b.wire.presentation_digest
                    || recipe_digest != b.wire.recipe_digest
                    || ready_challenge != r.challenge
                    || activate_ready_digest != r.digest
                {
                    return Err(rejected("Activate Final mismatch"));
                }
                b.read.service()?.require_same(&service)?;
                b.check()?;
                self.core
                    .phase
                    .step(self.target.index(), ACTIVATE_READY, ACTIVATE_ADMITTED)?;
                Ok(SignerFinancialWorkflowRequestV1::ActivateFinal(
                    SignerActivateFinalV1 {
                        binding: Arc::clone(r),
                    },
                ))
            }
            _ => Err(rejected("wrong writer action request")),
        }
    }
}
fn require_new_deadline(action: Instant, source: Instant) -> Result<()> {
    let now = Instant::now();
    if action <= now || action > source || action > now + std::time::Duration::from_secs(120) {
        return Err(rejected("writer action original deadline rejected"));
    }
    Ok(())
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_activate_read(
        &self,
        mut ticket: SignerActivateReadTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerActivateReadOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign Activate Read native ticket"));
        }
        serving.matches_acquire(&self.core, &ticket.binding.acquired_presentation)?;
        let service = serving.retain()?;
        ticket.binding.bind_service(service.correlation())?;
        ticket.check_current()?;
        service.check()?;
        self.core.phase.step(
            ticket.binding.slot(),
            ACTIVATE_READ_REVIEW,
            ACTIVATE_READ_ADMITTED,
        )?;
        ticket.consumed = true;
        Ok(SignerActivateReadOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            service,
            consumed: false,
        })
    }
    pub fn arm_activate(
        &self,
        mut ticket: SignerActivateReviewTicketV1,
    ) -> Result<SignerActivateArmOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign Activate native ticket"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.slot(), ACTIVATE_REVIEW, ACTIVATE_ARMED)?;
        ticket.consumed = true;
        Ok(SignerActivateArmOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
    pub fn admit_activate(
        &self,
        mut ticket: SignerActivateReadyTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerActivateFinalOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.review.core()) {
            self.revoke();
            return Err(rejected("foreign Activate native Ready"));
        }
        serving.matches_acquire(
            &self.core,
            &ticket.binding.review.read.acquired_presentation,
        )?;
        let service = serving.retain()?;
        ticket
            .binding
            .review
            .read
            .service()?
            .require_same(&service.correlation())?;
        ticket.check_current()?;
        service.check()?;
        self.core.phase.step(
            ticket.binding.review.slot(),
            ACTIVATE_READY,
            ACTIVATE_ADMITTED,
        )?;
        ticket.consumed = true;
        Ok(SignerActivateFinalOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            service,
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_activate_read(&mut self, outbound: SignerActivateReadOutboundV1) -> Result<()> {
        self.try_send_activate_read(outbound)?.require_sent()
    }
    pub fn try_send_activate_read(
        &mut self,
        mut outbound: SignerActivateReadOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = &outbound.binding;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core())
            || self.slots[i].as_ref().is_none_or(|s| {
                s.wire_phase != ACTIVATE_READ_REVIEW
                    || s.activate.read.as_ref().is_none_or(|r| !Arc::ptr_eq(r, b))
            })
        {
            return Err(rejected("foreign or repeated Activate Read outbound"));
        }
        b.check_bounds()?;
        outbound.service.check_bounds()?;
        b.service()?.require_same(&outbound.service.correlation())?;
        if self
            .core
            .phase
            .source_send_restricted(i, ACTIVATE_READ_ADMITTED)?
        {
            outbound.consumed = true;
            return Ok(FinancialSendProgressV1::Restricted);
        }
        let progress = self.send_positive(
            &Packet::ActivateReadFinal {
                actor: b.wire.actor.clone(),
                presentation_digest: b.wire.presentation_digest.clone(),
                read_challenge: b.wire.read_challenge.clone(),
                service: outbound.service.correlation(),
            },
            b.ceiling.min(b.service()?.deadline),
        )?;
        if progress == FinancialSendProgressV1::Sent {
            self.slots[i].as_mut().unwrap().wire_phase = ACTIVATE_READ_ADMITTED;
        }
        outbound.consumed = true;
        Ok(progress)
    }
    pub fn send_activate_arm(&mut self, outbound: SignerActivateArmOutboundV1) -> Result<()> {
        self.try_send_activate_arm(outbound)?.require_sent()
    }
    pub fn try_send_activate_arm(
        &mut self,
        mut outbound: SignerActivateArmOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = &outbound.binding;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core())
            || self.slots[i].as_ref().is_none_or(|s| {
                s.wire_phase != ACTIVATE_REVIEW
                    || s.activate
                        .review
                        .as_ref()
                        .is_none_or(|r| !Arc::ptr_eq(r, b))
            })
        {
            return Err(rejected("foreign or repeated Activate Arm outbound"));
        }
        b.check_bounds()?;
        if self.core.phase.source_send_restricted(i, ACTIVATE_ARMED)? {
            outbound.consumed = true;
            return Ok(FinancialSendProgressV1::Restricted);
        }
        let progress = self.send_positive(
            &Packet::ActivateArm {
                actor: b.wire.actor.clone(),
                presentation_digest: b.wire.presentation_digest.clone(),
                recipe_digest: b.wire.recipe_digest.clone(),
            },
            b.ceiling.min(b.read.service()?.deadline),
        )?;
        if progress == FinancialSendProgressV1::Sent {
            self.slots[i].as_mut().unwrap().wire_phase = ACTIVATE_ARMED;
        }
        outbound.consumed = true;
        Ok(progress)
    }
    pub fn send_activate_final(&mut self, outbound: SignerActivateFinalOutboundV1) -> Result<()> {
        self.try_send_activate_final(outbound)?.require_sent()
    }
    pub fn try_send_activate_final(
        &mut self,
        mut outbound: SignerActivateFinalOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let r = &outbound.binding;
        let b = &r.review;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core())
            || self.slots[i].as_ref().is_none_or(|s| {
                s.wire_phase != ACTIVATE_READY
                    || s.activate
                        .ready
                        .as_ref()
                        .is_none_or(|ready| !Arc::ptr_eq(ready, r))
            })
        {
            return Err(rejected("foreign or repeated Activate Final outbound"));
        }
        b.check_bounds()?;
        outbound.service.check_bounds()?;
        b.read
            .service()?
            .require_same(&outbound.service.correlation())?;
        if self
            .core
            .phase
            .source_send_restricted(i, ACTIVATE_ADMITTED)?
        {
            outbound.consumed = true;
            return Ok(FinancialSendProgressV1::Restricted);
        }
        let progress = self.send_positive(
            &Packet::ActivateFinal {
                actor: b.wire.actor.clone(),
                presentation_digest: b.wire.presentation_digest.clone(),
                recipe_digest: b.wire.recipe_digest.clone(),
                ready_challenge: r.challenge.clone(),
                activate_ready_digest: r.digest.clone(),
                service: outbound.service.correlation(),
            },
            b.ceiling.min(b.read.service()?.deadline),
        )?;
        if progress == FinancialSendProgressV1::Sent {
            self.slots[i].as_mut().unwrap().wire_phase = ACTIVATE_ADMITTED;
        }
        outbound.consumed = true;
        Ok(progress)
    }
    pub(super) fn receive_activate_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p
            .target()?
            .ok_or_else(|| rejected("writer event target missing"))?;
        let i = role.index();
        let slot = self.slots[i]
            .as_mut()
            .ok_or_else(|| rejected("unsolicited writer event"))?;
        if slot.failed || slot.activate.terminal {
            return Err(rejected("writer event after terminal"));
        }
        match p {
            Packet::ActivateReadDisplay { data } => {
                data.validate()?;
                let (acquired, committed, service, writer_deadline) =
                    slot.writer_acquire.retained_result()?;
                if slot.wire_phase != AWAITING_ACTIVATE_READ
                    || slot.activate.read_wire.is_some()
                    || !read_links_acquired(&data, acquired, committed)
                {
                    return Err(rejected("Activate Read display retained binding"));
                }
                slot.wire_phase = ACTIVATE_READ_REVIEW;
                slot.activate.read_wire = Some(data.clone());
                let entry = slot
                    .entry
                    .as_ref()
                    .ok_or_else(|| rejected("Activate Read original Entry missing"))?;
                let deadline = self.clocks.restrict_received(
                    PROFILE,
                    data.read_ceiling_ms,
                    entry.original_source,
                    Instant::now(),
                )?;
                let b = ActivateRead::from_bounds(
                    Arc::clone(entry),
                    data,
                    deadline,
                    acquired.clone(),
                    writer_deadline,
                    service.retained_restriction(),
                )?;
                slot.activate.read = Some(Arc::clone(&b));
                if !received_progress(
                    &self.core.phase,
                    i,
                    AWAITING_ACTIVATE_READ,
                    ACTIVATE_READ_REVIEW,
                )? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::ActivateReadDisplay(
                    SignerActivateReadTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::ActivateDisplay { data } => {
                data.validate()?;
                let read = slot
                    .activate
                    .read_wire
                    .as_ref()
                    .ok_or_else(|| rejected("Activate display before Activate Read"))?;
                if slot.wire_phase != ACTIVATE_READ_ADMITTED
                    || slot.activate.wire.is_some()
                    || !activate_links_read(&data, read)
                {
                    return Err(rejected("Activate display retained binding"));
                }
                slot.wire_phase = ACTIVATE_REVIEW;
                slot.activate.wire = Some(data.clone());
                let read = slot
                    .activate
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("Activate positive Activate Read missing"))?;
                let deadline = self.clocks.restrict_received(
                    PROFILE,
                    data.activate_ceiling_ms,
                    read.entry.original_source,
                    Instant::now(),
                )?;
                let b = ActivateReview::from_bounds(Arc::clone(read), data, deadline)?;
                slot.activate.review = Some(Arc::clone(&b));
                if !received_progress(&self.core.phase, i, ACTIVATE_READ_ADMITTED, ACTIVATE_REVIEW)?
                {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::ActivateDisplay(
                    SignerActivateReviewTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::ActivateReady {
                actor,
                presentation_digest,
                recipe_digest,
                ready_challenge,
                activate_ready_digest,
            } => {
                let wire = slot
                    .activate
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("Activate Ready before display"))?;
                if slot.wire_phase != ACTIVATE_ARMED
                    || slot.activate.observed_ready.is_some()
                    || actor != wire.actor
                    || presentation_digest != wire.presentation_digest
                    || recipe_digest != wire.recipe_digest
                    || !state::hash(&ready_challenge)
                    || !state::hash(&activate_ready_digest)
                {
                    return Err(rejected("Activate Ready binding"));
                }
                slot.wire_phase = ACTIVATE_READY;
                slot.activate.observed_ready = Some(activate_ready_digest.clone());
                let b = slot
                    .activate
                    .review
                    .as_ref()
                    .ok_or_else(|| rejected("Activate positive review missing"))?;
                b.check_bounds()?;
                let ready = Arc::new(ActivateReady {
                    review: Arc::clone(b),
                    challenge: ready_challenge,
                    digest: activate_ready_digest,
                });
                slot.activate.ready = Some(Arc::clone(&ready));
                if !received_progress(&self.core.phase, i, ACTIVATE_ARMED, ACTIVATE_READY)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::ActivateReady(
                    SignerActivateReadyTicketV1 {
                        binding: ready,
                        consumed: false,
                    },
                ))
            }
            Packet::ActivateReadFailed {
                actor,
                presentation_digest,
            } => {
                let read = slot
                    .activate
                    .read_wire
                    .as_ref()
                    .ok_or_else(|| rejected("Activate Read failure before display"))?;
                if !matches!(
                    slot.wire_phase,
                    ACTIVATE_READ_REVIEW | ACTIVATE_READ_ADMITTED
                ) || actor != read.actor
                    || presentation_digest != read.presentation_digest
                {
                    return Err(rejected("Activate Read failure binding"));
                }
                slot.activate.terminal = true;
                self.core.phase.revoke();
                if self.cleanup.is_none() {
                    self.cleanup = Some(self.clocks.first_cleanup_ceiling(Instant::now())?);
                }
                Ok(CoordinatorFinancialEventV1::ActivateReadFailed {
                    role,
                    presentation_digest,
                })
            }
            Packet::Activated { actor, data } => {
                data.validate()?;
                let r = slot
                    .activate
                    .ready
                    .as_ref()
                    .ok_or_else(|| rejected("Activate receipt before actual Ready"))?;
                let b = &r.review;
                let service = b.read.service()?;
                if slot.wire_phase != ACTIVATE_ADMITTED
                    || slot.activate.terminal
                    || slot.activate.committed.is_some()
                    || actor != b.wire.actor
                    || !activated_matches(&data, &b.wire, &r.digest, &service.digest)
                {
                    return Err(rejected("Activate receipt retained binding"));
                }
                self.core.phase.observe_workflow_activated_saved(i)?;
                slot.wire_phase = AWAITING_WALLET_PREPARE;
                slot.activate.committed = Some(data.clone());
                Ok(CoordinatorFinancialEventV1::AwaitingWalletPrepare { role, data })
            }
            Packet::ActivateOutcome { actor, data } => {
                data.validate()?;
                let p = slot
                    .activate
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("Activate outcome before display"))?;
                if slot.activate.committed.is_some()
                    || actor != p.actor
                    || !terminal_outcome_matches(
                        p,
                        slot.activate.observed_ready.as_deref(),
                        slot.wire_phase,
                        self.core.phase.revoked(),
                        &data,
                    )
                {
                    return Err(rejected("Activate terminal binding"));
                }
                slot.activate.terminal = true;
                self.core.phase.revoke();
                if self.cleanup.is_none() {
                    self.cleanup = Some(self.clocks.first_cleanup_ceiling(Instant::now())?);
                }
                Ok(CoordinatorFinancialEventV1::ActivateOutcome { role, data })
            }
            _ => Err(rejected("wrong writer action event")),
        }
    }
}
fn received_progress(phase: &Phases, slot: usize, from: u8, to: u8) -> Result<bool> {
    if phase.source_send_restricted(slot, from)? {
        return Ok(false);
    }
    match phase.step(slot, from, to) {
        Ok(()) => Ok(!phase.source_send_restricted(slot, to)?),
        Err(error) => {
            if phase.source_send_restricted(slot, from)? {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}
fn outcome_matches(
    p: &SignerActivatePresentationV1,
    ready: Option<&str>,
    data: &SignerActivateOutcomeV1,
) -> bool {
    let (presentation, digest) = data.parts();
    presentation == p.presentation_digest && digest == ready
}
fn terminal_outcome_matches(
    p: &SignerActivatePresentationV1,
    ready: Option<&str>,
    phase: u8,
    revoked: bool,
    data: &SignerActivateOutcomeV1,
) -> bool {
    let (presentation, digest) = data.parts();
    presentation == p.presentation_digest
        && match (ready, digest) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            (None, Some(b)) => revoked && phase == ACTIVATE_ARMED && state::hash(b),
            _ => false,
        }
}
impl HostFinancialWorkflowRelayV1 {
    pub(super) fn down_activate(&mut self, p: &Packet) -> Result<()> {
        let role = p
            .target()?
            .ok_or_else(|| rejected("writer relay command target missing"))?;
        if self.restricted {
            return Err(rejected("writer command after relay restriction"));
        }
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("writer relay slot missing"))?;
        if slot.failed || slot.activate.terminal {
            return Err(rejected("writer relay command after terminal"));
        }
        activate_current(slot, self.clocks)?;
        match p {
            Packet::ActivateReadFinal {
                actor,
                presentation_digest,
                read_challenge,
                service,
            } => {
                let r = slot
                    .activate
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Final before display"))?;
                if slot.phase != ACTIVATE_READ_REVIEW
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                    || read_challenge != &r.read_challenge
                    || !slot.activate.read_forwarded
                {
                    return Err(rejected("writer relay Read Final mismatch"));
                }
                slot.activate
                    .service
                    .as_ref()
                    .ok_or_else(|| rejected("retained Activate service missing"))?
                    .require_same(service)?;
                slot.phase = ACTIVATE_READ_ADMITTED;
                Ok(())
            }
            Packet::ActivateArm {
                actor,
                presentation_digest,
                recipe_digest,
            } => {
                let r = slot
                    .activate
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Arm before display"))?;
                if slot.phase != ACTIVATE_REVIEW
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                    || recipe_digest != &r.recipe_digest
                    || !slot.activate.display_forwarded
                {
                    return Err(rejected("writer relay Activate Arm mismatch"));
                }
                slot.phase = ACTIVATE_ARMED;
                Ok(())
            }
            Packet::ActivateFinal {
                actor,
                presentation_digest,
                recipe_digest,
                ready_challenge,
                activate_ready_digest,
                service,
            } => {
                let r = slot
                    .activate
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Final before display"))?;
                if slot.phase != ACTIVATE_READY
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                    || recipe_digest != &r.recipe_digest
                    || slot.activate.ready.as_ref()
                        != Some(&(ready_challenge.clone(), activate_ready_digest.clone()))
                {
                    return Err(rejected("writer relay Activate Final mismatch"));
                }
                slot.activate
                    .service
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay service missing"))?
                    .require_same(service)?;
                slot.phase = ACTIVATE_ADMITTED;
                Ok(())
            }
            _ => Err(rejected("wrong writer relay command")),
        }
    }
    pub(super) fn up_activate(&mut self, role: Target, p: &Packet) -> Result<bool> {
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("writer relay response slot missing"))?;
        if slot.failed || slot.activate.terminal {
            return Err(rejected("writer relay response after terminal"));
        }
        match p {
            Packet::ActivateReadDisplay { data } => {
                data.validate()?;
                let (acquired, committed, service, writer_deadline) =
                    slot.writer_acquire.retained_result()?;
                if slot.phase != AWAITING_ACTIVATE_READ
                    || slot.activate.read.is_some()
                    || !read_links_acquired(data, acquired, committed)
                {
                    return Err(rejected("writer relay display retained binding"));
                }
                slot.activate.service = Some(service.retained_restriction());
                slot.activate.writer_deadline = Some(writer_deadline);
                slot.activate.read = Some(data.clone());
                slot.activate.read_forwarded = !self.restricted;
                slot.phase = ACTIVATE_READ_REVIEW;
                if !self.restricted {
                    activate_current(slot, self.clocks)?;
                }
                Ok(!self.restricted)
            }
            Packet::ActivateDisplay { data } => {
                data.validate()?;
                let read = slot
                    .activate
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Activate before Read"))?;
                if slot.phase != ACTIVATE_READ_ADMITTED
                    || slot.activate.wire.is_some()
                    || !activate_links_read(data, read)
                {
                    return Err(rejected("writer relay Activate retained binding"));
                }
                slot.activate.wire = Some(data.clone());
                slot.activate.display_forwarded = !self.restricted;
                slot.phase = ACTIVATE_REVIEW;
                if !self.restricted {
                    activate_current(slot, self.clocks)?;
                }
                Ok(!self.restricted)
            }
            Packet::ActivateReady {
                actor,
                presentation_digest,
                recipe_digest,
                ready_challenge,
                activate_ready_digest,
            } => {
                let r = slot
                    .activate
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay Ready before display"))?;
                if slot.phase != ACTIVATE_ARMED
                    || slot.activate.ready.is_some()
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                    || recipe_digest != &r.recipe_digest
                    || !state::hash(ready_challenge)
                    || !state::hash(activate_ready_digest)
                {
                    return Err(rejected("writer relay Ready mismatch"));
                }
                slot.activate.ready =
                    Some((ready_challenge.clone(), activate_ready_digest.clone()));
                slot.phase = ACTIVATE_READY;
                if !self.restricted {
                    activate_current(slot, self.clocks)?;
                }
                Ok(!self.restricted)
            }
            Packet::ActivateReadFailed {
                actor,
                presentation_digest,
            } => {
                let r = slot
                    .activate
                    .read
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay failure before display"))?;
                if !matches!(slot.phase, ACTIVATE_READ_REVIEW | ACTIVATE_READ_ADMITTED)
                    || actor != &r.actor
                    || presentation_digest != &r.presentation_digest
                {
                    return Err(rejected("writer relay Read failure mismatch"));
                }
                let forward = slot.activate.read_forwarded;
                slot.activate.terminal = true;
                self.restrict()?;
                Ok(forward)
            }
            Packet::Activated { actor, data } => {
                data.validate()?;
                let p = slot
                    .activate
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("relay Activate receipt before display"))?;
                let ready = slot
                    .activate
                    .ready
                    .as_ref()
                    .ok_or_else(|| rejected("relay Activate receipt before Ready"))?;
                let service = slot
                    .activate
                    .service
                    .as_ref()
                    .ok_or_else(|| rejected("relay Activate receipt without service"))?;
                if slot.phase != ACTIVATE_ADMITTED
                    || slot.activate.terminal
                    || slot.activate.committed.is_some()
                    || actor != &p.actor
                    || !activated_matches(data, p, &ready.1, &service.digest)
                {
                    return Err(rejected("relay Activate receipt retained binding"));
                }
                slot.phase = AWAITING_WALLET_PREPARE;
                slot.activate.committed = Some(data.clone());
                Ok(true)
            }
            Packet::ActivateOutcome { actor, data } => {
                data.validate()?;
                let r = slot
                    .activate
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("writer relay outcome before display"))?;
                if slot.activate.committed.is_some()
                    || actor != &r.actor
                    || !outcome_matches(r, slot.activate.ready.as_ref().map(|r| r.1.as_str()), data)
                {
                    return Err(rejected("writer relay terminal mismatch"));
                }
                let forward = slot.activate.display_forwarded;
                slot.activate.terminal = true;
                self.restrict()?;
                Ok(forward)
            }
            _ => Err(rejected("wrong writer relay response")),
        }
    }
}
fn activate_current(slot: &mut HSlot, clocks: FullWorkflowClocksV1) -> Result<()> {
    if let Some(service) = &slot.activate.service {
        service.check()?;
    }
    crate::channel::require_time(
        slot.activate
            .writer_deadline
            .ok_or_else(|| rejected("Activate retained writer clock missing"))?,
    )?;
    let (source, action, start, end, source_wall) = if let Some(p) = &slot.activate.wire {
        (
            p.source_ceiling_ms,
            p.activate_ceiling_ms,
            p.facts.reviewed_at_ms,
            p.facts.expires_at_ms,
            p.facts.original.source_expires_at_ms,
        )
    } else {
        let p = slot
            .activate
            .read
            .as_ref()
            .ok_or_else(|| rejected("writer relay original display missing"))?;
        (
            p.source_ceiling_ms,
            p.read_ceiling_ms,
            p.facts.reviewed_at_ms,
            p.facts.expires_at_ms,
            p.facts.original.source_expires_at_ms,
        )
    };
    let now = Instant::now();
    for ms in [source, action] {
        clocks.restrict_received(PROFILE, ms, clocks.supervision(), now)?;
    }
    relay_wall(&mut slot.last_wall, start, end, source_wall)
}
impl SActivate {
    pub(super) fn disposal_allowed(&self) -> bool {
        self.read.is_none() || self.terminal || self.committed.is_some()
    }
}
impl CActivate {
    pub(super) fn disposal_allowed(&self) -> bool {
        self.read_wire.is_none() || self.terminal || self.committed.is_some()
    }
    pub(super) fn observe_active(&self, phase: u8) -> Result<()> {
        if matches!(phase, ACTIVATE_READ_REVIEW | ACTIVATE_READ_ADMITTED) {
            self.read
                .as_ref()
                .ok_or_else(|| rejected("active Activate Read binding missing"))?
                .check()?;
        } else if matches!(
            phase,
            ACTIVATE_REVIEW | ACTIVATE_ARMED | ACTIVATE_READY | ACTIVATE_ADMITTED
        ) {
            self.review
                .as_ref()
                .ok_or_else(|| rejected("active Activate binding missing"))?
                .check()?;
        }
        Ok(())
    }
}
impl HActivate {
    pub(super) fn disposal_allowed(&self) -> bool {
        self.read.is_none() || self.terminal || self.committed.is_some() || !self.read_forwarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activation_progress_preserves_r_and_rejects_q_or_wrong_phase() {
        for (from, to) in [
            (AWAITING_ACTIVATE_READ, ACTIVATE_READ_REVIEW),
            (ACTIVATE_READ_ADMITTED, ACTIVATE_REVIEW),
            (ACTIVATE_ARMED, ACTIVATE_READY),
        ] {
            let p = Phases::new();
            p.step(0, 0, from).unwrap();
            p.revoke();
            assert!(!received_progress(&p, 0, from, to).unwrap());
            assert_eq!(p.phase(0), from);
            assert!(received_progress(&p, 0, to, from).is_err());
            let q = Phases::new();
            q.step(1, 0, from).unwrap();
            q.begin_quiescence(q.snapshot()).unwrap();
            q.revoke();
            assert!(received_progress(&q, 1, from, to).is_err());
        }
    }
    #[test]
    fn activation_phases_are_separate_and_no_new_action_survives_r() {
        let p = Phases::new();
        p.step(0, 0, AWAITING_ACTIVATE_READ).unwrap();
        for (a, b) in [
            (47, 48),
            (48, 49),
            (49, 50),
            (50, 51),
            (51, 52),
            (52, 53),
            (53, 54),
        ] {
            p.step(0, a, b).unwrap();
            assert!(p.step(0, a, b).is_err());
        }
        p.revoke();
        p.observe_workflow_activated_saved(0).unwrap();
        assert_eq!(p.phase(0), AWAITING_WALLET_PREPARE);
        assert!(p
            .step(0, AWAITING_WALLET_PREPARE, ACTIVATE_READ_REVIEW)
            .is_err());
        assert!(p.observe_workflow_activated_saved(0).is_err());
    }
    #[test]
    fn read_matches_entire_actual_acquired_result_and_originals() {
        let mut read = crate::signer_activate_wallet_data::tests::read();
        let acquire = crate::signer_writer_read_acquire_data::tests::acquire(
            &crate::signer_writer_read_acquire_data::tests::read(),
        );
        read.facts.original.acquired.presentation_digest = acquire.presentation_digest.clone();
        read.facts.original.acquired.recipe_digest = acquire.recipe_digest.clone();
        let committed = read.facts.original.acquired.clone();
        assert!(read_links_acquired(&read, &acquire, &committed));
        let original = serde_json::to_value(&committed).unwrap();
        for key in original.as_object().unwrap().keys() {
            let mut changed = original.clone();
            match &mut changed[key] {
                serde_json::Value::String(s) => s.push('x'),
                serde_json::Value::Number(n) => *n = (n.as_u64().unwrap() + 1).into(),
                _ => panic!("closed acquired observation"),
            }
            let changed = serde_json::from_value(changed).unwrap();
            assert!(
                !read_links_acquired(&read, &acquire, &changed),
                "field {key}"
            );
        }
        let mut changed = read.clone();
        changed.facts.original.writer_selection_digest = "cd".repeat(32);
        assert!(!read_links_acquired(&changed, &acquire, &committed));
    }
    #[test]
    fn activation_recipe_and_authenticated_result_are_exact_not_retry_authority() {
        let p = crate::signer_activate_wallet_data::tests::activate();
        let read = crate::signer_activate_wallet_data::tests::read();
        assert!(activate_links_read(&p, &read));
        let ready = "cd".repeat(32);
        let service = "ef".repeat(32);
        let d = SignerActivateCommittedV1 {
            presentation_digest: p.presentation_digest.clone(),
            activate_ready_digest: ready.clone(),
            activation_request_digest: p.facts.activation_request_digest.clone(),
            signing_service_digest: service.clone(),
            session_id: p.facts.original.acquired.session_id.clone(),
            writer_epoch: p.facts.writer_epoch,
            head_sequence: p.facts.expected_head_sequence + 1,
            head_digest: "12".repeat(32),
        };
        assert!(activated_matches(&d, &p, &ready, &service));
        let original = serde_json::to_value(&d).unwrap();
        for key in original.as_object().unwrap().keys() {
            if key == "head_digest" {
                continue;
            } // authenticated owner supplies the new head
            let mut changed = original.clone();
            match &mut changed[key] {
                serde_json::Value::String(s) => s.push('x'),
                serde_json::Value::Number(n) => *n = (n.as_u64().unwrap() + 1).into(),
                _ => panic!("closed result"),
            }
            let changed = serde_json::from_value(changed).unwrap();
            assert!(
                !activated_matches(&changed, &p, &ready, &service),
                "field {key}"
            );
        }
        let mut changed = d.clone();
        changed.head_digest = p.facts.expected_head_digest.clone();
        assert!(!activated_matches(&changed, &p, &ready, &service));
        let mut changed = p.clone();
        changed.facts.original.acquired.session_id = "34".repeat(32);
        assert!(!activate_links_read(&changed, &read));
    }
    #[test]
    fn terminal_ready_race_never_widens_live_matching() {
        let p = crate::signer_activate_wallet_data::tests::activate();
        let d = SignerActivateOutcomeV1::Uncertain {
            presentation_digest: p.presentation_digest.clone(),
            activate_ready_digest: Some("cd".repeat(32)),
        };
        assert!(!terminal_outcome_matches(
            &p,
            None,
            ACTIVATE_ARMED,
            false,
            &d
        ));
        assert!(terminal_outcome_matches(&p, None, ACTIVATE_ARMED, true, &d));
        assert!(!terminal_outcome_matches(
            &p,
            None,
            ACTIVATE_REVIEW,
            true,
            &d
        ));
        assert!(!terminal_outcome_matches(
            &p,
            Some(&"ef".repeat(32)),
            ACTIVATE_ARMED,
            true,
            &d
        ));
    }
}
