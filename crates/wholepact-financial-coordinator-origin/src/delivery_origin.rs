//! One exact delivery slot. Public data is not authority. Only original-channel
//! receive mints tickets/tokens; only the thread-bound native issuer consumes
//! Arm/A. No lock, callback, caller event or FD import exists at those transitions.
use crate::{bootstrap::{self, InertTreeV1, LeafCustody}, delivery_channel::{Packet, DeliveryReviewInputsV1, DeliveryReviewPresentationV1, DeliveryReadyV1, DeliveryOutcomeV1}, process::PeerLifetime, rejected, Result, DeliveryFailureV1};
use std::{marker::PhantomData, os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd}, rc::Rc, sync::{Arc, atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

const NEW: u8 = 0;
const PREPARING: u8 = 1;
const REVIEW: u8 = 2;
const ARMED: u8 = 3;
const READY: u8 = 4;
const ADMITTED: u8 = 5;
const REVOKED: u8 = 128;
const GRANT_PENDING: u8 = 0;
const GRANT_SENT: u8 = 1;
const GRANT_ABANDONED: u8 = 2;

fn restrict_prepare_deadline(original: Instant, session: Instant, now: Instant) -> Result<Instant> {
    let deadline = original.min(now + Duration::from_secs(120)).min(session);
    if deadline <= now { return Err(rejected("original native preparation ceiling expired before send")); }
    Ok(deadline)
}
fn grant_pending(phase: u8, delivery: u8) -> bool { phase & !REVOKED == ADMITTED && delivery == GRANT_PENDING }

struct Phase(AtomicU8);
impl Phase {
    fn new() -> Self { Self(AtomicU8::new(NEW)) }
    fn load(&self) -> u8 { self.0.load(Ordering::Acquire) }
    fn step(&self, from: u8, to: u8) -> Result<()> {
        self.0.compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ()).map_err(|_| rejected("delivery slot transition refused"))
    }
    fn revoke(&self) { self.0.fetch_or(REVOKED, Ordering::AcqRel); }
    fn revoked(&self) -> bool { self.load() & REVOKED != 0 }
}

/// Private observation copies of the ACTUAL retained edge, never caller input.
/// No I/O API is exposed. Endpoint drop actively shuts down the shared socket,
/// so copies cannot suppress EOF or keep a discarded endpoint artificially live.
pub(super) struct ObservedPeer { pidfd: OwnedFd, socket: OwnedFd }
impl ObservedPeer {
    pub(super) fn retain(peer: &PeerLifetime, socket: RawFd) -> Result<Self> {
        peer.check_alive()?;
        let pidfd = duplicate(peer.fd())?;
        let socket = duplicate(socket)?;
        let result = Self { pidfd, socket };
        result.check()?;
        Ok(result)
    }
    fn check(&self) -> Result<()> {
        check_pidfd(&self.pidfd)?;
        let mut poll = libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0
            || poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        { return Err(rejected("original delivery edge lost")); }
        Ok(())
    }
    fn shut_down(&self) { unsafe { libc::shutdown(self.socket.as_raw_fd(), libc::SHUT_RDWR); } }
}
fn duplicate(fd: RawFd) -> Result<OwnedFd> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}
fn check_pidfd(fd: &OwnedFd) -> Result<()> {
    let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 || poll.revents != 0 {
        return Err(rejected("original delivery tree lifetime lost"));
    }
    Ok(())
}
fn nonce() -> Result<String> {
    let mut value = [0u8; 32];
    // Fresh AFTER separation, never cloned RNG state. No blocking entropy wait.
    if unsafe { libc::getrandom(value.as_mut_ptr().cast(), value.len(), libc::GRND_NONBLOCK) } != value.len() as isize {
        return Err(rejected("fresh delivery challenge unavailable"));
    }
    Ok(hex::encode(value))
}
fn hash(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn wall_ms() -> Result<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| rejected("wall clock before epoch"))?
        .as_millis().try_into().map_err(|_| rejected("wall clock overflow"))
}

struct Core {
    phase: Phase,
    peer: ObservedPeer,
    // C has exactly14 check-only lifetime copies; W has none here. Reapers stay
    // solely with the endpoint. Native Arm/A checks every original root child.
    roots: Vec<OwnedFd>,
    session_deadline: Instant,
    endpoint_alive: AtomicBool,
    admitted: AtomicBool,
    final_delivery: AtomicU8,
}
impl Core {
    fn check_alive(&self) -> Result<()> {
        let result = (|| {
            if !self.endpoint_alive.load(Ordering::Acquire) { return Err(rejected("delivery endpoint disposed")); }
            self.peer.check()?;
            for fd in &self.roots { check_pidfd(fd)?; }
            Ok(())
        })();
        if result.is_err() { self.phase.revoke(); }
        result
    }
    fn close(&self) {
        self.phase.revoke();
        self.endpoint_alive.store(false, Ordering::Release);
        self.peer.shut_down();
    }
}
struct ReviewBinding {
    core: Arc<Core>, session: String, nonce: String,
    data: DeliveryReviewPresentationV1, deadline: Instant, last_wall: AtomicU64,
}
impl ReviewBinding {
    fn check(&self) -> Result<()> {
        self.core.check_alive()?;
        let now = wall_ms()?;
        let previous = self.last_wall.fetch_max(now, Ordering::AcqRel);
        if now < previous || now < self.data.prepared_at_ms || now >= self.data.expires_at_ms
            || Instant::now() >= self.deadline || Instant::now() >= self.core.session_deadline
        { self.core.phase.revoke(); return Err(rejected("original delivery review expired or regressed")); }
        Ok(())
    }
}
struct ReadyBinding { review: Arc<ReviewBinding>, nonce: String, data: DeliveryReadyV1, deadline: Instant }
impl ReadyBinding {
    fn check(&self) -> Result<()> {
        self.review.check()?;
        let now = wall_ms()?;
        if now < self.data.accepted_at_ms || now >= self.data.accepted_tls_expires_at_ms || Instant::now() >= self.deadline {
            self.review.core.phase.revoke(); return Err(rejected("original accepted delivery call expired"));
        }
        Ok(())
    }
}
fn validate_review(data: &DeliveryReviewPresentationV1) -> Result<()> {
    if data.version != 1 || data.purpose != "coordinated-witness-durable-delivery-review"
        || data.mode != "one-exact-delivery-append" || data.display.is_empty() || data.display.len() > 64 * 1024 - 2048
        || data.expires_at_ms.checked_sub(data.prepared_at_ms).is_none_or(|n| n == 0 || n > 120_000)
        || data.operation_id.is_empty() || data.operation_id.len() > 128
        || !data.operation_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        || [&data.backend_review_digest, &data.presentation_digest, &data.account_id,
            &data.request_commitment, &data.source_commitment, &data.owner_certificate_digest, &data.expected_head_digest]
            .iter().any(|s| !hash(s))
    { return Err(rejected("invalid exact delivery review binding")); }
    Ok(())
}
fn validate_ready(p: &DeliveryReviewPresentationV1, data: &DeliveryReadyV1) -> Result<()> {
    if data.presentation_digest != p.presentation_digest || data.request_commitment != p.request_commitment
        || data.source_commitment != p.source_commitment || data.owner_certificate_digest != p.owner_certificate_digest
        || data.expected_head_sequence != p.expected_head_sequence || data.expected_head_digest != p.expected_head_digest
        || !hash(&data.effect_commitment) || !hash(&data.preparation_nonce)
        || data.accepted_at_ms < p.prepared_at_ms || data.accepted_at_ms >= p.expires_at_ms
        || data.accepted_tls_expires_at_ms.checked_sub(data.accepted_at_ms).is_none_or(|n| n == 0 || n > 10_000)
    { return Err(rejected("Ready does not match the one original armed review")); }
    Ok(())
}
fn validate_outcome(review: &DeliveryReviewPresentationV1, ready: Option<&DeliveryReadyV1>, data: &DeliveryOutcomeV1, admitted: bool) -> Result<()> {
    let (presentation, effect) = match data {
        DeliveryOutcomeV1::Committed { presentation_digest, effect_commitment, head_sequence, head_digest } => {
            if !admitted || review.expected_head_sequence.checked_add(1) != Some(*head_sequence) || !hash(head_digest) {
                return Err(rejected("committed outcome does not match the one append"));
            }
            (presentation_digest, Some(effect_commitment))
        }
        DeliveryOutcomeV1::KnownNoEffect { presentation_digest, effect_commitment }
        | DeliveryOutcomeV1::Uncertain { presentation_digest, effect_commitment } => (presentation_digest, effect_commitment.as_ref()),
    };
    if presentation != &review.presentation_digest
        || match (effect, ready) { (Some(effect), Some(ready)) => effect != &ready.effect_commitment, (None, None) => false, _ => true }
    { return Err(rejected("terminal delivery outcome binding mismatch")); }
    Ok(())
}

pub struct CoordinatorDeliveryNativeV1 {
    core: Arc<Core>, armed: Option<Arc<ReviewBinding>>, _native_thread: PhantomData<Rc<()>>,
}
pub struct CoordinatorDeliveryEndpointV1 {
    tree: Option<InertTreeV1>, core: Arc<Core>, session: String,
    prepare_deadline: Option<Instant>, review: Option<Arc<ReviewBinding>>, ready: Option<Arc<ReadyBinding>>,
    cancel_sent: bool, outcome_seen: bool, disposed: bool, failed: bool, cleanup_deadline: Option<Instant>, first_failure_seen: bool,
}
pub struct DeliveryReviewTicketV1 { binding: Arc<ReviewBinding>, consumed: bool }
impl DeliveryReviewTicketV1 { pub fn presentation(&self) -> &DeliveryReviewPresentationV1 { &self.binding.data } }
impl Drop for DeliveryReviewTicketV1 { fn drop(&mut self) { if !self.consumed { self.binding.core.phase.revoke(); } } }
pub struct DeliveryReadyTicketV1 { binding: Arc<ReadyBinding>, consumed: bool }
impl Drop for DeliveryReadyTicketV1 { fn drop(&mut self) { if !self.consumed { self.binding.review.core.phase.revoke(); } } }
pub struct DeliveryArmOutboundV1 { binding: Arc<ReviewBinding>, consumed: bool }
impl Drop for DeliveryArmOutboundV1 { fn drop(&mut self) { if !self.consumed { self.binding.core.phase.revoke(); } } }
pub struct DeliveryFinalOutboundV1 { binding: Arc<ReadyBinding>, consumed: bool }
impl Drop for DeliveryFinalOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.review.core.final_delivery.store(GRANT_ABANDONED, Ordering::Release);
            self.binding.review.core.phase.revoke();
        }
    }
}
pub enum CoordinatorDeliveryEventV1 {
    Prepared(DeliveryReviewTicketV1), Ready(DeliveryReadyTicketV1), Outcome(DeliveryOutcomeV1), PreparationFailed, Disposed, FirstFailure(DeliveryFailureV1),
}

pub(super) fn split_coordinator(tree: InertTreeV1, session_deadline: Instant) -> Result<(CoordinatorDeliveryNativeV1, CoordinatorDeliveryEndpointV1)> {
    let peer = tree.witness()?.delivery_observer()?;
    let roots = Vec::from(tree.observation_pidfds()?);
    let core = Arc::new(Core { phase: Phase::new(), peer, roots, session_deadline,
        endpoint_alive: AtomicBool::new(true), admitted: AtomicBool::new(false), final_delivery: AtomicU8::new(GRANT_PENDING) });
    let session = nonce()?;
    let native = CoordinatorDeliveryNativeV1 { core: Arc::clone(&core), armed: None, _native_thread: PhantomData };
    let endpoint = CoordinatorDeliveryEndpointV1 { tree: Some(tree), core, session, prepare_deadline: None,
        review: None, ready: None, cancel_sent: false, outcome_seen: false, disposed: false, failed: false, cleanup_deadline: None, first_failure_seen: false };
    Ok((native, endpoint))
}
impl CoordinatorDeliveryNativeV1 {
    pub fn session_deadline(&self) -> Instant { self.core.session_deadline }
    pub fn is_revoked(&self) -> bool { self.core.phase.revoked() }
    pub fn was_admitted(&self) -> bool { self.core.admitted.load(Ordering::Acquire) }
    pub fn revoke(&self) { self.core.phase.revoke(); }
    pub fn check_current(&self) -> Result<()> {
        self.core.check_alive()?;
        if self.is_revoked() || Instant::now() >= self.core.session_deadline { self.revoke(); return Err(rejected("native delivery session revoked")); }
        if let Some(review) = &self.armed { review.check()?; }
        Ok(())
    }
    /// Called only by the reviewed genuine final-primary-click path. The whole
    /// pinned native image supplies gesture correctness; origin does not prove it.
    pub fn arm(&mut self, mut ticket: DeliveryReviewTicketV1) -> Result<DeliveryArmOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.core) || self.armed.is_some() { self.revoke(); return Err(rejected("foreign or repeated native Arm")); }
        ticket.binding.check()?;
        self.core.phase.step(REVIEW, ARMED)?;
        ticket.consumed = true;
        self.armed = Some(Arc::clone(&ticket.binding));
        Ok(DeliveryArmOutboundV1 { binding: Arc::clone(&ticket.binding), consumed: false })
    }
    /// A occurs HERE, at visible native-loop tail after its complete immutable
    /// input batch and cancellation handling. Endpoint dequeue/send is not A.
    pub fn admit(&mut self, mut ticket: DeliveryReadyTicketV1) -> Result<DeliveryFinalOutboundV1> {
        if self.armed.as_ref().is_none_or(|review| !Arc::ptr_eq(review, &ticket.binding.review))
            || !Arc::ptr_eq(&self.core, &ticket.binding.review.core)
        { self.revoke(); return Err(rejected("foreign Ready ticket")); }
        ticket.binding.check()?;
        let grant = DeliveryFinalOutboundV1 { binding: Arc::clone(&ticket.binding), consumed: false };
        self.core.phase.step(READY, ADMITTED)?;
        self.core.admitted.store(true, Ordering::Release);
        ticket.consumed = true;
        Ok(grant)
    }
}
impl Drop for CoordinatorDeliveryNativeV1 { fn drop(&mut self) { self.revoke(); } }
impl CoordinatorDeliveryEndpointV1 {
    fn tree(&self) -> Result<&InertTreeV1> { self.tree.as_ref().ok_or_else(|| rejected("delivery tree consumed")) }
    fn send(&self, packet: &Packet) -> Result<()> {
        self.core.check_alive()?;
        let result = self.tree()?.witness()?.delivery_send(packet);
        if result.is_err() { self.core.phase.revoke(); }
        result
    }
    pub fn session_deadline(&self) -> Instant { self.core.session_deadline }
    pub fn is_revoked(&self) -> bool { self.core.phase.revoked() }
    pub fn was_admitted(&self) -> bool { self.core.admitted.load(Ordering::Acquire) }
    pub fn revoke(&self) { self.core.phase.revoke(); }
    pub fn check_alive(&self) -> Result<()> { self.core.check_alive() }
    pub fn send_prepare_once(&mut self, input: DeliveryReviewInputsV1, original_native_ceiling: Instant) -> Result<()> {
        self.core.phase.step(NEW, PREPARING)?;
        let deadline = match restrict_prepare_deadline(original_native_ceiling, self.core.session_deadline, Instant::now()) {
            Ok(deadline) => deadline,
            Err(error) => { self.revoke(); return Err(error); }
        };
        self.prepare_deadline = Some(deadline);
        self.send(&Packet::PrepareOnce { session: self.session.clone(), input })
    }
    pub fn send_arm(&mut self, mut grant: DeliveryArmOutboundV1) -> Result<()> {
        if self.review.as_ref().is_none_or(|r| !Arc::ptr_eq(r, &grant.binding)) || self.core.phase.load() != ARMED {
            self.revoke(); return Err(rejected("Arm outbound slot mismatch"));
        }
        grant.binding.check()?;
        self.send(&Packet::Arm { session: self.session.clone(), review_nonce: grant.binding.nonce.clone(), presentation_digest: grant.binding.data.presentation_digest.clone() })?;
        grant.consumed = true;
        Ok(())
    }
    pub fn send_final_admit(&mut self, mut grant: DeliveryFinalOutboundV1) -> Result<()> {
        if self.outcome_seen || self.disposed || self.ready.as_ref().is_none_or(|r| !Arc::ptr_eq(r, &grant.binding))
            || self.core.phase.load() & !REVOKED != ADMITTED || self.core.final_delivery.load(Ordering::Acquire) != GRANT_PENDING
        { self.revoke(); return Err(rejected("Final outbound slot mismatch")); }
        grant.binding.check()?;
        self.send(&Packet::FinalAdmit { session: self.session.clone(), review_nonce: grant.binding.review.nonce.clone(), ready_nonce: grant.binding.nonce.clone(), effect_commitment: grant.binding.data.effect_commitment.clone() })?;
        self.core.final_delivery.store(GRANT_SENT, Ordering::Release);
        grant.consumed = true;
        Ok(())
    }
    pub fn admitted_grant_pending(&self) -> bool {
        grant_pending(self.core.phase.load(), self.core.final_delivery.load(Ordering::Acquire))
    }
    pub fn send_cancel(&mut self) -> Result<()> {
        self.revoke();
        if self.admitted_grant_pending() { return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)); }
        if self.cancel_sent { return Err(rejected("second delivery Cancel")); }
        self.cleanup_deadline.get_or_insert((Instant::now() + Duration::from_secs(5)).min(self.core.session_deadline + Duration::from_secs(5)));
        self.send(&Packet::Cancel { session: self.session.clone() })?;
        self.cancel_sent = true;
        Ok(())
    }
    pub fn try_receive_delivery_event(&mut self) -> Result<Option<CoordinatorDeliveryEventV1>> {
        let result = self.receive_event();
        if result.is_err() { self.revoke(); }
        result
    }
    fn receive_event(&mut self) -> Result<Option<CoordinatorDeliveryEventV1>> {
        self.core.check_alive()?;
        let Some(packet) = self.tree()?.witness()?.delivery_receive()? else { return Ok(None); };
        match packet {
            Packet::PreparedDisplay { session, review_nonce, data } if session == self.session && self.review.is_none() && self.core.phase.load() & !REVOKED == PREPARING => {
                validate_review(&data)?;
                if !hash(&review_nonce) { return Err(rejected("invalid review challenge")); }
                let now = wall_ms()?;
                let remaining = data.expires_at_ms.checked_sub(now).filter(|n| *n > 0).ok_or_else(|| rejected("expired received review"))?;
                let deadline = self.prepare_deadline.ok_or_else(|| rejected("missing original prepare clock"))?.min(Instant::now() + Duration::from_millis(remaining));
                let binding = Arc::new(ReviewBinding { core: Arc::clone(&self.core), session, nonce: review_nonce, data, deadline, last_wall: AtomicU64::new(now) });
                binding.check()?;
                self.review = Some(Arc::clone(&binding));
                if self.core.phase.step(PREPARING, REVIEW).is_err() { return Ok(None); }
                Ok(Some(CoordinatorDeliveryEventV1::Prepared(DeliveryReviewTicketV1 { binding, consumed: false })))
            }
            Packet::Ready { session, review_nonce, ready_nonce, data } if session == self.session && self.ready.is_none() && self.core.phase.load() & !REVOKED == ARMED => {
                let review = self.review.as_ref().ok_or_else(|| rejected("Ready before review"))?;
                if review_nonce != review.nonce || !hash(&ready_nonce) { return Err(rejected("Ready challenge mismatch")); }
                validate_ready(&review.data, &data)?;
                let remaining = data.accepted_tls_expires_at_ms.checked_sub(wall_ms()?).filter(|n| *n > 0).ok_or_else(|| rejected("expired received Ready"))?;
                let binding = Arc::new(ReadyBinding { review: Arc::clone(review), nonce: ready_nonce, deadline: review.deadline.min(Instant::now() + Duration::from_millis(remaining)), data });
                binding.check()?;
                self.ready = Some(Arc::clone(&binding));
                if self.core.phase.step(ARMED, READY).is_err() { return Ok(None); }
                Ok(Some(CoordinatorDeliveryEventV1::Ready(DeliveryReadyTicketV1 { binding, consumed: false })))
            }
            Packet::Outcome { session, review_nonce, data } if session == self.session && !self.outcome_seen => {
                let review = self.review.as_ref().ok_or_else(|| rejected("outcome before original review"))?;
                if review_nonce != review.nonce { return Err(rejected("outcome review challenge mismatch")); }
                validate_outcome(&review.data, self.ready.as_ref().map(|ready| &ready.data), &data, self.was_admitted())?;
                self.outcome_seen = true;
                self.revoke();
                Ok(Some(CoordinatorDeliveryEventV1::Outcome(data)))
            }
            Packet::FirstFailure { session, data } if session == self.session && !self.first_failure_seen && !self.disposed && !self.outcome_seen && !self.failed && self.prepare_deadline.is_some() => {
                self.first_failure_seen = true; Ok(Some(CoordinatorDeliveryEventV1::FirstFailure(data)))
            }
            Packet::PreparationFailed { session } if session == self.session && !self.failed && self.review.is_none() && self.prepare_deadline.is_some() => {
                self.failed = true; self.revoke(); Ok(Some(CoordinatorDeliveryEventV1::PreparationFailed))
            }
            Packet::Disposed { session } if session == self.session && !self.disposed && (self.cancel_sent || self.outcome_seen || self.failed) => {
                self.disposed = true; self.revoke(); Ok(Some(CoordinatorDeliveryEventV1::Disposed))
            }
            _ => Err(rejected("duplicate or out-of-phase delivery response")),
        }
    }
    pub fn stop_and_reap(mut self, deadline: Instant) -> Result<()> {
        if !self.disposed || !self.cancel_sent { return Err(rejected("delivery disposal handshake incomplete")); }
        let cleanup = self.cleanup_deadline.unwrap_or(deadline);
        self.tree.take().ok_or_else(|| rejected("delivery tree consumed"))?.stop_and_reap(deadline.min(cleanup).min(self.core.session_deadline + Duration::from_secs(5)))
    }
}
impl Drop for CoordinatorDeliveryEndpointV1 { fn drop(&mut self) { self.core.close(); } }

pub struct WitnessDeliveryOriginV1 {
    leaf: Option<LeafCustody>, core: Arc<Core>, session: Option<String>, review: Option<Arc<ReviewBinding>>,
    ready: Option<Arc<ReadyBinding>>, cancel_seen: bool, outcome_sent: bool, disposed: bool, failed: bool, first_failure_sent: bool,
}
pub enum WitnessDeliveryRequestV1 { PrepareOnce(DeliveryReviewInputsV1), Arm(WitnessDeliveryArmV1), FinalAdmit(WitnessDeliveryFinalAdmitV1), Cancel }
pub struct WitnessDeliveryArmV1 { review: Arc<ReviewBinding> }
impl WitnessDeliveryArmV1 {
    pub fn presentation_digest(&self) -> &str { &self.review.data.presentation_digest }
    pub fn prepared_at_ms(&self) -> u64 { self.review.data.prepared_at_ms }
    pub fn expires_at_ms(&self) -> u64 { self.review.data.expires_at_ms }
    pub fn check_original_coordinator_alive(&self) -> Result<()> {
        self.review.check()?;
        if self.review.core.phase.revoked() { return Err(rejected("delivery Arm revoked")); }
        Ok(())
    }
}
pub struct WitnessDeliveryFinalAdmitV1 { ready: Arc<ReadyBinding> }
impl WitnessDeliveryFinalAdmitV1 {
    pub fn presentation_digest(&self) -> &str { &self.ready.review.data.presentation_digest }
    pub fn prepared_at_ms(&self) -> u64 { self.ready.review.data.prepared_at_ms }
    pub fn expires_at_ms(&self) -> u64 { self.ready.review.data.expires_at_ms }
    pub fn effect_commitment(&self) -> &str { &self.ready.data.effect_commitment }
    /// Zero-wait actual pidfd/channel and original clock checks. Late restriction
    /// does not retroactively un-admit; Authority may still conservatively refuse
    /// before P and must report the exact terminal outcome, never a new attempt.
    pub fn check_original_coordinator_alive(&self) -> Result<()> { self.ready.check() }
}
impl WitnessDeliveryOriginV1 {
    pub(super) fn from_leaf(leaf: LeafCustody) -> Result<Self> {
        let peer = leaf.origin.delivery_observer()?;
        let core = Arc::new(Core { phase: Phase::new(), peer, roots: Vec::new(), session_deadline: leaf.clocks.session,
            endpoint_alive: AtomicBool::new(true), admitted: AtomicBool::new(false), final_delivery: AtomicU8::new(GRANT_PENDING) });
        Ok(Self { leaf: Some(leaf), core, session: None, review: None, ready: None, cancel_seen: false, outcome_sent: false, disposed: false, failed: false, first_failure_sent: false })
    }
    fn leaf(&self) -> Result<&LeafCustody> { self.leaf.as_ref().ok_or_else(|| rejected("W delivery origin consumed")) }
    fn session(&self) -> Result<String> { self.session.clone().ok_or_else(|| rejected("W delivery session absent")) }
    fn send(&self, packet: &Packet) -> Result<()> {
        self.core.check_alive()?;
        let result = self.leaf()?.origin.delivery_send(packet);
        if result.is_err() { self.core.phase.revoke(); }
        result
    }
    pub fn session_deadline(&self) -> Instant { self.core.session_deadline }
    pub fn check_coordinator_alive(&self) -> Result<()> { self.core.check_alive() }
    pub fn try_receive_delivery_request(&mut self) -> Result<Option<WitnessDeliveryRequestV1>> {
        let result = self.receive_request();
        if result.is_err() { self.core.phase.revoke(); }
        result
    }
    fn receive_request(&mut self) -> Result<Option<WitnessDeliveryRequestV1>> {
        self.core.check_alive()?;
        let Some(packet) = self.leaf()?.origin.delivery_receive()? else { return Ok(None); };
        match packet {
            Packet::PrepareOnce { session, input } if self.session.is_none() && hash(&session) => {
                self.core.phase.step(NEW, PREPARING)?;
                self.session = Some(session); Ok(Some(WitnessDeliveryRequestV1::PrepareOnce(input)))
            }
            Packet::Arm { session, review_nonce, presentation_digest } if Some(&session) == self.session.as_ref() => {
                let review = self.review.as_ref().ok_or_else(|| rejected("Arm before W display"))?;
                if review_nonce != review.nonce || presentation_digest != review.data.presentation_digest { return Err(rejected("W Arm binding mismatch")); }
                review.check()?;
                self.core.phase.step(REVIEW, ARMED)?;
                Ok(Some(WitnessDeliveryRequestV1::Arm(WitnessDeliveryArmV1 { review: Arc::clone(review) })))
            }
            Packet::FinalAdmit { session, review_nonce, ready_nonce, effect_commitment } if Some(&session) == self.session.as_ref() => {
                let ready = self.ready.as_ref().ok_or_else(|| rejected("FinalAdmit before W Ready"))?;
                if review_nonce != ready.review.nonce || ready_nonce != ready.nonce || effect_commitment != ready.data.effect_commitment { return Err(rejected("W FinalAdmit binding mismatch")); }
                ready.check()?;
                self.core.phase.step(READY, ADMITTED)?;
                self.core.admitted.store(true, Ordering::Release);
                Ok(Some(WitnessDeliveryRequestV1::FinalAdmit(WitnessDeliveryFinalAdmitV1 { ready: Arc::clone(ready) })))
            }
            Packet::Cancel { session } if !self.cancel_seen && hash(&session) && self.session.as_ref().is_none_or(|old| old == &session) => {
                self.session = Some(session); self.cancel_seen = true; self.core.phase.revoke();
                Ok(Some(WitnessDeliveryRequestV1::Cancel))
            }
            _ => Err(rejected("duplicate or out-of-phase W delivery input")),
        }
    }
    pub fn send_display(&mut self, data: DeliveryReviewPresentationV1, original_review_deadline: Instant) -> Result<()> {
        validate_review(&data)?;
        if self.review.is_some() { return Err(rejected("second W delivery display")); }
        let binding = Arc::new(ReviewBinding { core: Arc::clone(&self.core), session: self.session()?, nonce: nonce()?,
            deadline: original_review_deadline.min(self.core.session_deadline), last_wall: AtomicU64::new(data.prepared_at_ms), data });
        binding.check()?;
        self.core.phase.step(PREPARING, REVIEW)?;
        let packet = Packet::PreparedDisplay { session: binding.session.clone(), review_nonce: binding.nonce.clone(), data: binding.data.clone() };
        self.review = Some(binding);
        self.send(&packet)
    }
    pub fn send_ready(&mut self, data: DeliveryReadyV1, original_tls_deadline: Instant) -> Result<()> {
        let review = self.review.as_ref().ok_or_else(|| rejected("W Ready before original display"))?;
        if self.ready.is_some() { return Err(rejected("second W delivery Ready")); }
        validate_ready(&review.data, &data)?;
        let ready = Arc::new(ReadyBinding { review: Arc::clone(review), nonce: nonce()?, deadline: original_tls_deadline.min(review.deadline), data });
        ready.check()?;
        self.core.phase.step(ARMED, READY)?;
        let packet = Packet::Ready { session: review.session.clone(), review_nonce: review.nonce.clone(), ready_nonce: ready.nonce.clone(), data: ready.data.clone() };
        self.ready = Some(ready);
        self.send(&packet)
    }
    pub fn send_outcome(&mut self, data: DeliveryOutcomeV1) -> Result<()> {
        if self.outcome_sent || self.failed { return Err(rejected("second W delivery outcome")); }
        let review = self.review.as_ref().ok_or_else(|| rejected("W outcome before original display"))?;
        validate_outcome(&review.data, self.ready.as_ref().map(|ready| &ready.data), &data, self.core.admitted.load(Ordering::Acquire))?;
        self.outcome_sent = true;
        self.send(&Packet::Outcome { session: review.session.clone(), review_nonce: review.nonce.clone(), data })
    }
    pub fn send_first_failure(&mut self, data: DeliveryFailureV1) -> Result<()> {
        if self.first_failure_sent || self.disposed || self.outcome_sent || self.failed || self.review.is_none() && self.core.phase.load() & !REVOKED != PREPARING { return Err(rejected("duplicate or late W first failure")); }
        self.first_failure_sent = true;
        self.send(&Packet::FirstFailure { session: self.session()?, data })
    }
    pub fn send_preparation_failed(&mut self) -> Result<()> {
        if self.failed || self.review.is_some() || self.outcome_sent { return Err(rejected("invalid W preparation failure phase")); }
        self.failed = true;
        self.send(&Packet::PreparationFailed { session: self.session()? })
    }
    pub fn send_disposed(&mut self) -> Result<()> {
        if self.disposed || (!self.cancel_seen && !self.outcome_sent && !self.failed) { return Err(rejected("invalid W disposal phase")); }
        self.disposed = true;
        self.send(&Packet::Disposed { session: self.session()? })
    }
    pub fn complete(mut self, work: Result<()>) -> ! {
        let work = work.and_then(|()| if self.disposed && self.cancel_seen { Ok(()) } else { Err(rejected("W delivery disposal handshake incomplete")) });
        let result = match self.leaf.take() { Some(leaf) => bootstrap::finish_leaf(leaf, work), None => Err(rejected("W delivery custody missing")) };
        drop(self);
        bootstrap::child_exit(result)
    }
}
impl Drop for WitnessDeliveryOriginV1 { fn drop(&mut self) { self.core.close(); } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revoke_before_admit_is_permanent_but_late_revoke_retains_admitted_phase() {
        let phase = Phase::new();
        phase.step(NEW, READY).unwrap();
        phase.revoke();
        assert!(phase.step(READY, ADMITTED).is_err());
        assert_eq!(phase.load(), READY | REVOKED);
        let phase = Phase::new();
        phase.step(NEW, READY).unwrap();
        phase.step(READY, ADMITTED).unwrap();
        phase.revoke();
        assert_eq!(phase.load(), ADMITTED | REVOKED);
        assert!(phase.step(READY, ADMITTED).is_err());
    }
    fn presentation() -> DeliveryReviewPresentationV1 {
        DeliveryReviewPresentationV1 { version: 1, purpose: "coordinated-witness-durable-delivery-review".into(),
            mode: "one-exact-delivery-append".into(), display: "ordinary test data, not a source or ticket".into(),
            backend_review_digest: "a".repeat(64), presentation_digest: "b".repeat(64), prepared_at_ms: 1000, expires_at_ms: 121000,
            account_id: "c".repeat(64), operation_id: "operation:one".into(), request_commitment: "d".repeat(64),
            source_commitment: "e".repeat(64), owner_certificate_digest: "f".repeat(64), expected_head_sequence: 7, expected_head_digest: "1".repeat(64) }
    }
    fn ready(p: &DeliveryReviewPresentationV1) -> DeliveryReadyV1 {
        DeliveryReadyV1 { presentation_digest: p.presentation_digest.clone(), effect_commitment: "2".repeat(64),
            request_commitment: p.request_commitment.clone(), source_commitment: p.source_commitment.clone(),
            owner_certificate_digest: p.owner_certificate_digest.clone(), expected_head_sequence: p.expected_head_sequence,
            expected_head_digest: p.expected_head_digest.clone(), preparation_nonce: "3".repeat(64), accepted_at_ms: 120000, accepted_tls_expires_at_ms: 130000 }
    }
    #[test]
    fn pending_admitted_grant_precedes_cancel_but_sent_or_abandoned_does_not() {
        for phase in [ADMITTED, ADMITTED | REVOKED] {
            assert!(grant_pending(phase, GRANT_PENDING));
            assert!(!grant_pending(phase, GRANT_SENT));
            assert!(!grant_pending(phase, GRANT_ABANDONED));
        }
        for phase in [NEW, PREPARING, REVIEW, ARMED, READY, READY | REVOKED] { assert!(!grant_pending(phase, GRANT_PENDING)); }
    }
    #[test]
    fn every_original_slot_transition_is_one_use() {
        let phase = Phase::new();
        for (from, to) in [(NEW, PREPARING), (PREPARING, REVIEW), (REVIEW, ARMED), (ARMED, READY), (READY, ADMITTED)] {
            phase.step(from, to).unwrap(); assert!(phase.step(from, to).is_err());
        }
        phase.revoke(); assert!(phase.step(ADMITTED, NEW).is_err());
    }
    #[test]
    fn ready_rejects_mismatched_original_bindings_and_unrenewed_time_bounds() {
        let p = presentation(); validate_review(&p).unwrap(); let data = ready(&p);
        // TLS has its own original expiry, which may be later than review. Both
        // remain independently checked at runtime; this data check renews none.
        validate_ready(&p, &data).unwrap();
        for field in 0..6 {
            let mut bad = data.clone();
            match field { 0 => bad.presentation_digest = "0".repeat(64), 1 => bad.request_commitment = "0".repeat(64),
                2 => bad.source_commitment = "0".repeat(64), 3 => bad.owner_certificate_digest = "0".repeat(64),
                4 => bad.expected_head_sequence += 1, _ => bad.expected_head_digest = "0".repeat(64) }
            assert!(validate_ready(&p, &bad).is_err());
        }
        let mut bad = data.clone(); bad.accepted_at_ms = p.prepared_at_ms - 1; assert!(validate_ready(&p, &bad).is_err());
        let mut bad = data.clone(); bad.accepted_at_ms = p.expires_at_ms; bad.accepted_tls_expires_at_ms = p.expires_at_ms + 10_000; assert!(validate_ready(&p, &bad).is_err());
        let mut bad = data.clone(); bad.accepted_tls_expires_at_ms += 1; assert!(validate_ready(&p, &bad).is_err());
        let mut bad = data.clone(); bad.accepted_tls_expires_at_ms = bad.accepted_at_ms; assert!(validate_ready(&p, &bad).is_err());
        let mut bad = data; bad.preparation_nonce.clear(); assert!(validate_ready(&p, &bad).is_err());
    }
    #[test]
    fn exact_terminal_outcome_cannot_substitute_effect_or_committed_head() {
        let p = presentation(); let r = ready(&p);
        let committed = DeliveryOutcomeV1::Committed { presentation_digest: p.presentation_digest.clone(), effect_commitment: r.effect_commitment.clone(), head_sequence: 8, head_digest: "4".repeat(64) };
        validate_outcome(&p, Some(&r), &committed, true).unwrap();
        assert!(validate_outcome(&p, Some(&r), &committed, false).is_err());
        assert!(validate_outcome(&p, None, &committed, true).is_err());
        let mut wrong = committed.clone(); if let DeliveryOutcomeV1::Committed { head_sequence, .. } = &mut wrong { *head_sequence = 9; }
        assert!(validate_outcome(&p, Some(&r), &wrong, true).is_err());
        let no_effect = DeliveryOutcomeV1::KnownNoEffect { presentation_digest: p.presentation_digest.clone(), effect_commitment: None };
        validate_outcome(&p, None, &no_effect, false).unwrap(); assert!(validate_outcome(&p, Some(&r), &no_effect, false).is_err());
        let uncertain = DeliveryOutcomeV1::Uncertain { presentation_digest: p.presentation_digest.clone(), effect_commitment: Some(r.effect_commitment.clone()) };
        validate_outcome(&p, Some(&r), &uncertain, true).unwrap();
        let mut wrong = r; wrong.effect_commitment = "5".repeat(64); assert!(validate_outcome(&p, Some(&wrong), &uncertain, true).is_err());
    }

    #[test]
    fn queued_prepare_cannot_start_after_original_native_ceiling() {
        let start = Instant::now(); let original = start + Duration::from_secs(120); let session = start + Duration::from_secs(300);
        assert_eq!(restrict_prepare_deadline(original, session, start + Duration::from_secs(20)).unwrap(), original);
        assert!(restrict_prepare_deadline(original, session, original).is_err());
        assert!(restrict_prepare_deadline(original, session, original + Duration::from_secs(1)).is_err());
        assert!(restrict_prepare_deadline(original, start, start).is_err());
        assert_eq!(restrict_prepare_deadline(session, session, start).unwrap(), original);
    }

}
