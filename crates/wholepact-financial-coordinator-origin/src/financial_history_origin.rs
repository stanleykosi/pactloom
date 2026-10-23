//! Actual fixed initial-owner-history W custody. No public constructor, role,
//! packet, descriptor or DTO can mint Setup or Serve. Read output always obeys R.

macro_rules! actor_boundary {($stage:ident,$class:ident,$peer:expr)=>{{
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] {use crate::financial_ci_actor_diagnostics as d;d::origin(d::OriginStage::$stage,d::Class::$class,$peer);}
}};}
use crate::{
    bootstrap::{self, LeafCustody},
    channel::require_time,
    financial_history_channel::{self as wire, Packet, Setup},
    financial_history_data::{
        FinancialHistoryInputsV1, FinancialHistoryPresentationV1, FinancialHistoryReadBindingV1,
    },
    financial_workflow_clock::{FullWorkflowClocksV1, PROFILE},
    financial_workflow_source::wall_ceiling,
    host_restriction::WitnessSharedRestrictionV1,
    rejected,
    signer_continue_state::{self as state, CheckedPeer},
    Result,
};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    time::Instant,
};
const SETUP: u8 = 1;
const REVIEW: u8 = 2;
const SERVING: u8 = 3;
struct HistoryCore {
    peer: CheckedPeer,
    restriction: WitnessSharedRestrictionV1,
    clocks: FullWorkflowClocksV1,
    pid: libc::pid_t,
    uid: libc::uid_t,
    alive: AtomicBool,
    restricted: AtomicBool,
    phase: AtomicU8,
}
impl HistoryCore {
    fn actors(&self) -> Result<()> {
        if !self.alive.load(Ordering::Acquire)
            || unsafe { libc::getpid() } != self.pid
            || unsafe { libc::geteuid() } != self.uid
        {
            actor_boundary!(ActorCustody,PredicateDenied,None);
            return Err(rejected("initial history original actor lost"));
        }
        self.peer.check()
    }
    fn action(&self) -> Result<()> {
        self.actors()?;
        require_time(self.clocks.supervision()).inspect_err(|_error| {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            crate::financial_ci_actor_diagnostics::origin_io(crate::financial_ci_actor_diagnostics::OriginStage::SessionDeadline,_error,None);
        })?;
        if self.restricted.load(Ordering::Acquire) {
            actor_boundary!(ActionRevoked,Restricted,None);
            return Err(rejected("initial history restricted"));
        }
        self.restriction.check_current()
    }
    fn restrict(&self) {
        self.restricted.store(true, Ordering::Release);
    }
    fn close(&self) {
        self.restrict();
        self.alive.store(false, Ordering::Release);
        self.peer.shutdown();
    }
    fn step(&self, from: u8, to: u8) -> Result<()> {
        self.phase
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| rejected("initial history phase consumed"))
    }
}
struct SetupBinding {
    core: Arc<HistoryCore>,
    wire: Setup,
    setup_ceiling: Instant,
    read_ceiling: Instant,
    last_wall: AtomicU64,
}
impl SetupBinding {
    fn read_current(&self) -> Result<()> {
        self.core.action()?;
        require_time(self.read_ceiling).inspect_err(|_error| {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            crate::financial_ci_actor_diagnostics::origin_io(crate::financial_ci_actor_diagnostics::OriginStage::ReadDeadline,_error,None);
        })?;
        let f = &self.wire.read_binding.read.facts;
        let wall = state::observe_shared_wall(
            &self.last_wall,
            self.read_ceiling.min(self.core.clocks.supervision()),
            state::wall_ms,
        )?
        .ok_or_else(|| rejected("initial history original Read clock"))?;
        if wall < f.reviewed_at_ms
            || wall >= f.expires_at_ms
            || wall >= f.source_expires_at_ms
        {
            return Err(rejected("initial history original Read clock"));
        }
        Ok(())
    }
    fn setup_current(&self) -> Result<()> {
        self.read_current()?;
        require_time(self.setup_ceiling)
    }
}
struct ReviewBinding {
    setup: Arc<SetupBinding>,
    data: FinancialHistoryPresentationV1,
    challenge: String,
    ceiling: Instant,
    last_wall: AtomicU64,
}
impl ReviewBinding {
    fn current(&self) -> Result<()> {
        self.setup.read_current()?;
        require_time(self.ceiling).inspect_err(|_error| {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            crate::financial_ci_actor_diagnostics::origin_io(crate::financial_ci_actor_diagnostics::OriginStage::BoundDeadline,_error,None);
        })?;
        let wall = state::observe_shared_wall(
            &self.last_wall,
            self.ceiling.min(self.setup.read_ceiling).min(self.setup.core.clocks.supervision()),
            state::wall_ms,
        )?
        .ok_or_else(|| rejected("initial history prepared source clock"))?;
        if wall < self.data.prepared_at_ms || wall >= self.data.expires_at_ms {
            return Err(rejected("initial history prepared source clock"));
        }
        Ok(())
    }
}
/// Only original C's focused Setup receive authorizes protected preparation.
pub struct WitnessFinancialHistorySetupV1 {
    binding: Arc<SetupBinding>,
}
impl WitnessFinancialHistorySetupV1 {
    pub fn inputs(&self) -> &FinancialHistoryInputsV1 {
        &self.binding.wire.inputs
    }
    pub fn read_binding(&self) -> &FinancialHistoryReadBindingV1 {
        &self.binding.wire.read_binding
    }
    pub fn original_setup_deadline(&self) -> Instant {
        self.binding.setup_ceiling
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.read_ceiling
    }
    pub fn check_original_coordinator_alive(&self) -> Result<()> {
        self.binding.core.actors()
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.setup_current()?;
        if self.binding.core.phase.load(Ordering::Acquire) != SETUP {
            return Err(rejected("initial history Setup consumed"));
        }
        Ok(())
    }
}
/// Separate Serve receive, bound to prepared actual owner-only source. This
/// never reopens key files and never gains a late-R completion exception.
pub struct WitnessFinancialHistoryServeV1 {
    binding: Arc<ReviewBinding>,
}
impl WitnessFinancialHistoryServeV1 {
    pub fn presentation(&self) -> &FinancialHistoryPresentationV1 {
        &self.binding.data
    }
    pub fn effective_io_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_original_coordinator_alive(&self) -> Result<()> {
        self.binding.setup.core.actors()
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current()?;
        if self.binding.setup.core.phase.load(Ordering::Acquire) != SERVING {
            return Err(rejected("initial history Serve not current"));
        }
        Ok(())
    }
}
pub enum FinancialHistoryRequestV1 {
    PrepareOnce(WitnessFinancialHistorySetupV1),
    Serve(WitnessFinancialHistoryServeV1),
    FinishRead,
    Cancel,
    ClosePurpose,
}
pub struct WitnessFinancialHistoryOriginV1 {
    core: Arc<HistoryCore>,
    leaf: Option<LeafCustody>,
    instance: String,
    setup: Option<Arc<SetupBinding>>,
    review: Option<Arc<ReviewBinding>>,
    coordinator: Option<(String, String)>,
    serving_ack: bool,
    finish_seen: bool,
    cancel_seen: bool,
    failed: bool,
    disposed: bool,
    close_seen: bool,
    closed: bool,
    cleanup: Option<Instant>,
}
impl WitnessFinancialHistoryOriginV1 {
    pub(super) fn from_leaf(
        leaf: LeafCustody,
        restriction: WitnessSharedRestrictionV1,
    ) -> Result<Self> {
        if !wire::is_history_witness(leaf.origin.role()) {
            return Err(rejected("not fixed initial history custody"));
        }
        let core = Arc::new(HistoryCore {
            peer: leaf.origin.continue_observer()?,
            restriction,
            clocks: leaf.clocks.workflow(),
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::geteuid() },
            alive: AtomicBool::new(true),
            restricted: AtomicBool::new(false),
            phase: AtomicU8::new(0),
        });
        core.action()?;
        Ok(Self {
            core,
            leaf: Some(leaf),
            instance: state::nonce()?,
            setup: None,
            review: None,
            coordinator: None,
            serving_ack: false,
            finish_seen: false,
            cancel_seen: false,
            failed: false,
            disposed: false,
            close_seen: false,
            closed: false,
            cleanup: None,
        })
    }
    pub fn session_deadline(&self) -> Instant {
        self.core.clocks.supervision()
    }
    pub fn check_original_coordinator_alive(&self) -> Result<()> {
        self.core.actors()
    }
    /// Monitor-only restriction check. It cannot create a worker permission.
    pub fn check_current(&self) -> Result<()> {
        if let Some(review) = &self.review {
            review.current()
        } else if let Some(setup) = &self.setup {
            setup.setup_current()
        } else {
            self.core.action()
        }
    }

    /// Restriction only, for actual monitor/worker failure before any cleanup.
    pub fn restrict(&self) {
        self.core.restrict();
    }
    /// Failure-only teardown: deny and close the actual control edge BEFORE
    /// an owned worker join that may block. This never reports disposal or
    /// successful grammar closure, and it creates no cleanup budget.
    pub fn close_for_failed_worker_v1(&mut self){
        self.failed=true;
        self.core.close();
        self.leaf.take();
    }
    pub fn retain_cleanup_deadline(&mut self, original: Instant) -> Result<Instant> {
        let value = self
            .core
            .clocks
            .retain_cleanup(self.cleanup, original, Instant::now())?;
        self.cleanup = Some(value);
        Ok(value)
    }
    pub fn original_cleanup_deadline(&self) -> Result<Instant> {
        self.cleanup
            .ok_or_else(|| rejected("initial history cleanup not started"))
    }
    fn first_cleanup(&mut self) -> Result<()> {
        self.retain_cleanup_deadline(self.core.clocks.hard_cleanup())?;
        Ok(())
    }
    fn transport(&self) -> Result<()> {
        self.core.actors()?;
        require_time(self.cleanup.unwrap_or(self.core.clocks.hard_cleanup()))
    }
    fn send(&self, packet: &Packet) -> Result<()> {
        self.transport()?;
        self.leaf
            .as_ref()
            .ok_or_else(|| rejected("initial history custody consumed"))?
            .origin
            .financial_history_send(packet)?;
        #[cfg(wholepact_financial_ci)]
        match packet {Packet::Serving{..}=>crate::financial_observer::purpose("PurposeServing")?,Packet::Disposed{..}=>crate::financial_observer::purpose("PurposeDisposed")?,Packet::PurposeClosed{..}=>crate::financial_observer::purpose("PurposeClosed")?,_=>{}}
        Ok(())
    }
    fn identity(&self, c: &str, s: &str) -> bool {
        self.coordinator
            .as_ref()
            .is_some_and(|(a, b)| a == c && b == s)
    }
    pub fn try_receive(&mut self) -> Result<Option<FinancialHistoryRequestV1>> {
        let result = self.receive_inner();
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if let Err(error)=&result {crate::financial_ci_actor_diagnostics::origin_io(crate::financial_ci_actor_diagnostics::OriginStage::WitnessReceive,error,None);}

        if result.is_err() {
            self.core.close();
        }
        result
    }
    fn receive_inner(&mut self) -> Result<Option<FinancialHistoryRequestV1>> {
        self.transport()?;
        let Some(packet) = self
            .leaf
            .as_ref()
            .ok_or_else(|| rejected("initial history custody consumed"))?
            .origin
            .financial_history_receive()?
        else {
            return Ok(None);
        };
        let request = match packet {
            Packet::PrepareOnce { setup } => {
                if self.setup.is_some() || self.cancel_seen || self.disposed {
                    return Err(rejected("initial history Setup reused"));
                }
                self.core.step(0, SETUP)?;
                setup.validate()?;
                self.core.action()?;
                let r = &setup.read_binding.read;
                if wire::role_for(r.actor.signer_role) != self.leaf.as_ref().unwrap().origin.role()
                {
                    return Err(rejected("initial history wrong owner slot"));
                }
                let now = Instant::now();
                let wall = state::wall_ms()?;
                let source = self.core.clocks.restrict_received(
                    PROFILE,
                    r.source_ceiling_ms,
                    self.core.clocks.supervision(),
                    now,
                )?;
                let read_ceiling = self
                    .core
                    .clocks
                    .restrict_received(PROFILE, r.read_ceiling_ms, source, now)?
                    .min(wall_ceiling(
                        now,
                        wall,
                        r.facts.reviewed_at_ms,
                        r.facts.expires_at_ms,
                    )?);
                let setup_ceiling = self.core.clocks.restrict_received(
                    PROFILE,
                    setup.setup_ceiling_ms,
                    read_ceiling,
                    now,
                )?;
                self.coordinator = Some((
                    r.actor.coordinator_process_instance.clone(),
                    r.actor.session_challenge.clone(),
                ));
                let b = Arc::new(SetupBinding {
                    core: Arc::clone(&self.core),
                    wire: setup,
                    setup_ceiling,
                    read_ceiling,
                    last_wall: AtomicU64::new(wall),
                });
                b.setup_current()?;
                self.setup = Some(Arc::clone(&b));
                FinancialHistoryRequestV1::PrepareOnce(WitnessFinancialHistorySetupV1 {
                    binding: b,
                })
            }
            Packet::Serve {
                setup_challenge,
                witness_instance,
                serve_challenge,
                presentation_digest,
            } => {
                if self.cancel_seen || self.failed || self.finish_seen || self.disposed {
                    return Err(rejected("initial history Serve after terminal"));
                }
                let b = self
                    .review
                    .as_ref()
                    .ok_or_else(|| rejected("initial history Serve before review"))?;
                if setup_challenge != b.setup.wire.setup_challenge
                    || witness_instance != self.instance
                    || serve_challenge != b.challenge
                    || presentation_digest != b.data.presentation_digest
                {
                    return Err(rejected("initial history Serve binding"));
                }
                b.current()?;
                self.core.step(REVIEW, SERVING)?;
                FinancialHistoryRequestV1::Serve(WitnessFinancialHistoryServeV1 {
                    binding: Arc::clone(b),
                })
            }
            Packet::FinishRead {
                setup_challenge,
                witness_instance,
                presentation_digest,
                read_presentation_digest,
            } => {
                let b = self
                    .review
                    .as_ref()
                    .ok_or_else(|| rejected("initial history Finish before review"))?;
                if !self.serving_ack
                    || self.finish_seen
                    || self.cancel_seen
                    || self.failed
                    || self.disposed
                    || setup_challenge != b.setup.wire.setup_challenge
                    || witness_instance != self.instance
                    || presentation_digest != b.data.presentation_digest
                    || read_presentation_digest
                        != b.setup.wire.read_binding.read.presentation_digest
                {
                    return Err(rejected("initial history Finish binding"));
                }
                // Authenticated C sends this only after actual matching S history
                // retention. It is restrictive cleanup, not a renewed Read grant.
                self.core.restrict();
                self.finish_seen = true;
                self.first_cleanup()?;
                FinancialHistoryRequestV1::FinishRead
            }
            Packet::Cancel {
                coordinator,
                session,
            } => {
                if self.cancel_seen
                    || self.closed
                    || !state::hash(&coordinator)
                    || !state::hash(&session)
                {
                    return Err(rejected("initial history repeated Cancel"));
                }
                if self.coordinator.is_none() {
                    self.coordinator = Some((coordinator.clone(), session.clone()));
                }
                if !self.identity(&coordinator, &session) {
                    return Err(rejected("initial history Cancel identity"));
                }
                self.core.restrict();
                self.cancel_seen = true;
                self.first_cleanup()?;
                FinancialHistoryRequestV1::Cancel
            }
            Packet::ClosePurpose {
                coordinator,
                session,
            } => {
                if !self.identity(&coordinator, &session) || !self.disposed || self.close_seen {
                    return Err(rejected("initial history close before disposal"));
                }
                self.first_cleanup()?;
                self.close_seen = true;
                FinancialHistoryRequestV1::ClosePurpose
            }
            _ => return Err(rejected("unexpected initial history command")),
        };
        Ok(Some(request))
    }
    pub fn send_display(&mut self, data: FinancialHistoryPresentationV1) -> Result<()> {
        if self.review.is_some() || self.failed || self.cancel_seen || self.disposed {
            return Err(rejected("initial history Display repeated"));
        }
        let setup = self
            .setup
            .as_ref()
            .ok_or_else(|| rejected("initial history Display before Setup"))?;
        setup.setup_current()?;
        data.validate()?;
        if data.read_binding != setup.wire.read_binding
            || data.account_id != setup.wire.inputs.expected_account_id
            || data.network_profile_id != setup.wire.inputs.network_profile_id
        {
            return Err(rejected("initial history source changed binding"));
        }
        let now = Instant::now();
        let wall = state::wall_ms()?;
        let ceiling = setup.read_ceiling.min(wall_ceiling(
            now,
            wall,
            data.prepared_at_ms,
            data.expires_at_ms,
        )?);
        let b = Arc::new(ReviewBinding {
            setup: Arc::clone(setup),
            data: data.clone(),
            challenge: state::nonce()?,
            ceiling,
            last_wall: AtomicU64::new(wall),
        });
        b.current()?;
        self.core.step(SETUP, REVIEW)?;
        self.review = Some(Arc::clone(&b));
        self.send(&Packet::Display {
            setup_challenge: setup.wire.setup_challenge.clone(),
            witness_instance: self.instance.clone(),
            serve_challenge: b.challenge.clone(),
            read_ceiling_ms: setup.wire.read_binding.read.read_ceiling_ms,
            data,
        })
    }
    /// The actual worker has accepted its genuine Serve and retained the bounded
    /// listener/service before this acknowledgement. No public DTO can create it.
    pub fn acknowledge_serving(&mut self) -> Result<()> {
        if self.serving_ack || self.core.phase.load(Ordering::Acquire) != SERVING {
            return Err(rejected("initial history Serving repeated"));
        }
        let b = self
            .review
            .as_ref()
            .ok_or_else(|| rejected("initial history review missing"))?;
        b.current()?;
        self.serving_ack = true;
        self.send(&Packet::Serving {
            setup_challenge: b.setup.wire.setup_challenge.clone(),
            witness_instance: self.instance.clone(),
            serve_challenge: b.challenge.clone(),
            presentation_digest: b.data.presentation_digest.clone(),
        })
    }
    pub fn send_preparation_failed(&mut self) -> Result<()> {
        if self.failed || self.review.is_some() || self.disposed {
            return Err(rejected("initial history preparation failure phase"));
        }
        self.core.restrict();
        self.failed = true;
        self.first_cleanup()?;
        let setup = self
            .setup
            .as_ref()
            .ok_or_else(|| rejected("initial history failure before Setup"))?;
        self.send(&Packet::PreparationFailed {
            setup_challenge: setup.wire.setup_challenge.clone(),
        })
    }
    pub fn send_service_failed(&mut self) -> Result<()> {
        if self.failed || self.disposed {
            return Err(rejected("initial history service failure repeated"));
        }
        self.core.restrict();
        self.failed = true;
        self.first_cleanup()?;
        let b = self
            .review
            .as_ref()
            .ok_or_else(|| rejected("initial history failure before review"))?;
        self.send(&Packet::ServiceFailed {
            setup_challenge: b.setup.wire.setup_challenge.clone(),
            witness_instance: self.instance.clone(),
            presentation_digest: b.data.presentation_digest.clone(),
        })
    }
    /// Only after successful join has dropped the real listener, TLS, socket,
    /// namespace and journal. A timeout/panic cannot claim this observation.
    pub fn send_disposed(&mut self) -> Result<()> {
        if self.disposed || (!self.finish_seen && !self.cancel_seen && !self.failed) {
            return Err(rejected("initial history disposal phase"));
        }
        self.first_cleanup()?;
        let cleanup_ceiling_ms = self
            .core
            .clocks
            .cleanup_offset(self.original_cleanup_deadline()?)?;
        let (c, s) = self
            .coordinator
            .as_ref()
            .ok_or_else(|| rejected("initial history disposal identity"))?;
        self.send(&Packet::Disposed {
            coordinator: c.clone(),
            session: s.clone(),
            cleanup_ceiling_ms,
        })?;
        self.disposed = true;
        Ok(())
    }
    pub fn send_purpose_closed(&mut self) -> Result<()> {
        if !self.close_seen || !self.disposed || self.closed {
            return Err(rejected("initial history grammar not closed"));
        }
        let (c, s) = self
            .coordinator
            .as_ref()
            .ok_or_else(|| rejected("initial history close identity"))?;
        self.send(&Packet::PurposeClosed {
            coordinator: c.clone(),
            session: s.clone(),
        })?;
        self.closed = true;
        Ok(())
    }
    pub fn complete(mut self, work: Result<()>) -> ! {
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if let Err(error)=&work {crate::financial_ci_actor_diagnostics::work_fallback(crate::financial_ci_actor_diagnostics::DriverStage::WitnessWork,error);}

        let result = (|| {
            work?;
            if !self.disposed || !self.closed {
                return Err(rejected("initial history terminal handshake incomplete"));
            }
            let leaf = self
                .leaf
                .take()
                .ok_or_else(|| rejected("initial history custody consumed"))?;
            bootstrap::finish_leaf_capped(leaf, Ok(()), self.cleanup)
        })();
        self.core.close();
        bootstrap::child_exit(result)
    }
}
impl Drop for WitnessFinancialHistoryOriginV1 {
    fn drop(&mut self) {
        self.core.close();
    }
}
