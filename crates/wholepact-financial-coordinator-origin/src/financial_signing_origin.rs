//! Actual fixed original-signing W custody. Setup and retained service are
//! distinct from per-request maintained financial authority. New I/O obeys R.
use crate::{
    bootstrap::{self, LeafCustody},
    channel::require_time,
    financial_signing_channel::{self as wire, Packet, Setup},
    financial_signing_data::{
        FinancialSigningInputsV1, FinancialSigningPresentationV1, FinancialSigningOriginalV1,
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
struct SigningCore {
    peer: CheckedPeer,
    restriction: WitnessSharedRestrictionV1,
    clocks: FullWorkflowClocksV1,
    pid: libc::pid_t,
    uid: libc::uid_t,
    alive: AtomicBool,
    restricted: AtomicBool,
    phase: AtomicU8,
}
impl SigningCore {
    fn actors(&self) -> Result<()> {
        if !self.alive.load(Ordering::Acquire)
            || unsafe { libc::getpid() } != self.pid
            || unsafe { libc::geteuid() } != self.uid
        {
            return Err(rejected("financial signing original actor lost"));
        }
        self.peer.check()
    }
    fn action(&self) -> Result<()> {
        self.actors()?;
        require_time(self.clocks.supervision())?;
        if self.restricted.load(Ordering::Acquire) {
            return Err(rejected("financial signing restricted"));
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
            .map_err(|_| rejected("financial signing phase consumed"))
    }
}
struct SetupBinding {
    core: Arc<SigningCore>, wire: Setup, setup_ceiling:Instant, source_ceiling:Instant,
    last_wall:AtomicU64,
}
impl SetupBinding {
    fn source_current(&self)->Result<()> {
        self.core.action()?; require_time(self.source_ceiling)?;
        let wall=state::wall_ms()?;let old=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<old||wall>=self.wire.original.source_expires_at_ms {
            return Err(rejected("financial signing original source clock"));
        } Ok(())
    }
    fn setup_current(&self)->Result<()> {self.source_current()?;require_time(self.setup_ceiling)}
}
struct ReviewBinding {
    setup:Arc<SetupBinding>, data:FinancialSigningPresentationV1, challenge:String,
    original_service:Instant, service_ceiling:Instant, review_ceiling:Instant,
    last_wall:AtomicU64,
}
impl ReviewBinding {
    // Completed Setup approval is NOT an ancestor of the service lifetime.
    fn service_current(&self)->Result<()> {
        self.setup.source_current()?;require_time(self.service_ceiling)?;
        let wall=state::wall_ms()?;let old=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<old||wall<self.data.valid_from_ms||wall>=self.data.valid_until_ms {
            return Err(rejected("financial signing original service clock"));
        } Ok(())
    }
    fn review_current(&self)->Result<()> {
        self.service_current()?;require_time(self.review_ceiling)?;
        if state::wall_ms()? >= self.data.expires_at_ms{return Err(rejected("financial signing Setup review elapsed"));} Ok(())
    }
}
/// Received once from the actual original C edge, never from an ordinary DTO.
pub struct WitnessFinancialSigningSetupV1 {binding:Arc<SetupBinding>}
impl WitnessFinancialSigningSetupV1 {
    pub fn inputs(&self)->&FinancialSigningInputsV1{&self.binding.wire.inputs}
    pub fn original_binding(&self)->&FinancialSigningOriginalV1{&self.binding.wire.original}
    pub fn original_setup_deadline(&self)->Instant{self.binding.setup_ceiling}
    pub fn original_source_deadline(&self)->Instant{self.binding.source_ceiling}
    pub fn check_original_coordinator_alive(&self)->Result<()>{self.binding.core.actors()}
    pub fn check_current(&self)->Result<()>{self.binding.setup_current()?;
        if self.binding.core.phase.load(Ordering::Acquire)!=SETUP{return Err(rejected("financial signing Setup consumed"));}Ok(())}
}
/// Original bounded resource/service permission, not approval for any financial
/// mutation. Each request samples this before the unchanged maintained dispatch;
/// an admitted mutation retains its existing commit semantics after that sample.
pub struct WitnessFinancialSigningServeV1 {binding:Arc<ReviewBinding>}
impl WitnessFinancialSigningServeV1 {
    pub fn presentation(&self)->&FinancialSigningPresentationV1{&self.binding.data}
    pub fn original_service_deadline(&self)->Instant{self.binding.original_service}
    pub fn effective_io_deadline(&self)->Instant{self.binding.service_ceiling}
    pub fn check_original_coordinator_alive(&self)->Result<()>{self.binding.setup.core.actors()}
    pub fn check_current(&self)->Result<()>{self.binding.service_current()?;
        if self.binding.setup.core.phase.load(Ordering::Acquire)!=SERVING{return Err(rejected("financial signing Serve not current"));}Ok(())}
}
pub enum FinancialSigningRequestV1 {
    PrepareOnce(WitnessFinancialSigningSetupV1),
    Serve(WitnessFinancialSigningServeV1),
    FinishService,
    Cancel,
    ClosePurpose,
}
pub struct WitnessFinancialSigningOriginV1 {
    core: Arc<SigningCore>,
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
impl WitnessFinancialSigningOriginV1 {
    pub(super) fn from_leaf(
        leaf: LeafCustody,
        restriction: WitnessSharedRestrictionV1,
    ) -> Result<Self> {
        if !wire::is_signing_witness(leaf.origin.role()) {
            return Err(rejected("not fixed financial signing custody"));
        }
        let core = Arc::new(SigningCore {
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
            if self.core.phase.load(Ordering::Acquire)==SERVING { review.service_current() } else { review.review_current() }
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
            .ok_or_else(|| rejected("financial signing cleanup not started"))
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
            .ok_or_else(|| rejected("financial signing custody consumed"))?
            .origin
            .financial_signing_send(packet)
    }
    fn identity(&self, c: &str, s: &str) -> bool {
        self.coordinator
            .as_ref()
            .is_some_and(|(a, b)| a == c && b == s)
    }
    pub fn try_receive(&mut self) -> Result<Option<FinancialSigningRequestV1>> {
        let result = self.receive_inner();
        if result.is_err() {
            self.core.close();
        }
        result
    }
    fn receive_inner(&mut self) -> Result<Option<FinancialSigningRequestV1>> {
        self.transport()?;
        let Some(packet) = self
            .leaf
            .as_ref()
            .ok_or_else(|| rejected("financial signing custody consumed"))?
            .origin
            .financial_signing_receive()?
        else {
            return Ok(None);
        };
        let request = match packet {
            Packet::PrepareOnce { setup } => {
                if self.setup.is_some() || self.cancel_seen || self.disposed {
                    return Err(rejected("financial signing Setup reused"));
                }
                self.core.step(0, SETUP)?;
                setup.validate()?;
                self.core.action()?;
                let o=&setup.original;
                if wire::role_for(o.actor.signer_role)!=self.leaf.as_ref().unwrap().origin.role(){return Err(rejected("financial signing wrong owner slot"));}
                let now=Instant::now();let wall=state::wall_ms()?;
                let source_ceiling=self.core.clocks.restrict_received(PROFILE,o.source_ceiling_ms,self.core.clocks.supervision(),now)?;
                let setup_ceiling=self.core.clocks.restrict_received(PROFILE,setup.setup_ceiling_ms,source_ceiling,now)?;
                if setup_ceiling.duration_since(now)>std::time::Duration::from_secs(120){return Err(rejected("financial signing Setup ceiling too wide"));}
                self.coordinator=Some((o.actor.coordinator_process_instance.clone(),o.actor.session_challenge.clone()));
                let b=Arc::new(SetupBinding{core:Arc::clone(&self.core),wire:setup,setup_ceiling,source_ceiling,last_wall:AtomicU64::new(wall)});
                b.setup_current()?;
                self.setup = Some(Arc::clone(&b));
                FinancialSigningRequestV1::PrepareOnce(WitnessFinancialSigningSetupV1 {
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
                    return Err(rejected("financial signing Serve after terminal"));
                }
                let b = self
                    .review
                    .as_ref()
                    .ok_or_else(|| rejected("financial signing Serve before review"))?;
                if setup_challenge != b.setup.wire.setup_challenge
                    || witness_instance != self.instance
                    || serve_challenge != b.challenge
                    || presentation_digest != b.data.presentation_digest
                {
                    return Err(rejected("financial signing Serve binding"));
                }
                b.review_current()?;
                self.core.step(REVIEW, SERVING)?;
                b.service_current()?;
                FinancialSigningRequestV1::Serve(WitnessFinancialSigningServeV1 {
                    binding: Arc::clone(b),
                })
            }
            Packet::FinishService {
                setup_challenge,
                witness_instance,
                presentation_digest,
            } => {
                let b = self
                    .review
                    .as_ref()
                    .ok_or_else(|| rejected("financial signing Finish before review"))?;
                if !self.serving_ack
                    || self.finish_seen
                    || self.cancel_seen
                    || self.failed
                    || self.disposed
                    || setup_challenge != b.setup.wire.setup_challenge
                    || witness_instance != self.instance
                    || presentation_digest != b.data.presentation_digest
                {
                    return Err(rejected("financial signing Finish binding"));
                }
                // Authenticated C can only shorten this service. This is not a
                // completed financial effect or permission to start another one.
                self.core.restrict();
                self.finish_seen = true;
                self.first_cleanup()?;
                FinancialSigningRequestV1::FinishService
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
                    return Err(rejected("financial signing repeated Cancel"));
                }
                if self.coordinator.is_none() {
                    self.coordinator = Some((coordinator.clone(), session.clone()));
                }
                if !self.identity(&coordinator, &session) {
                    return Err(rejected("financial signing Cancel identity"));
                }
                self.core.restrict();
                self.cancel_seen = true;
                self.first_cleanup()?;
                FinancialSigningRequestV1::Cancel
            }
            Packet::ClosePurpose {
                coordinator,
                session,
            } => {
                if !self.identity(&coordinator, &session) || !self.disposed || self.close_seen {
                    return Err(rejected("financial signing close before disposal"));
                }
                self.first_cleanup()?;
                self.close_seen = true;
                FinancialSigningRequestV1::ClosePurpose
            }
            _ => return Err(rejected("unexpected financial signing command")),
        };
        Ok(Some(request))
    }
    pub fn send_display(&mut self,data:FinancialSigningPresentationV1,original_service_deadline:Instant)->Result<()> {
        if self.review.is_some()||self.failed||self.cancel_seen||self.disposed{return Err(rejected("financial signing Display repeated"));}
        let setup=self.setup.as_ref().ok_or_else(||rejected("financial signing Display before Setup"))?;
        setup.setup_current()?;data.validate()?;
        let selected=&setup.wire.inputs.selectors;
        if data.original!=setup.wire.original||data.account_id!=selected.expected_account_id
            ||data.network_profile_id!=selected.network_profile_id||data.operation_id!=setup.wire.inputs.continuation_operation_id
            ||data.endpoint!=selected.endpoint||data.server_name!=selected.server_name||data.witness_id!=selected.witness_id
            ||data.pinned_server_certificate_digest!=selected.pinned_server_certificate_digest {
            return Err(rejected("financial signing source changed binding"));
        }
        let now=Instant::now();let wall=state::wall_ms()?;
        if wall<data.valid_from_ms||wall>=data.valid_until_ms{return Err(rejected("financial signing original service wall bound"));}
        let wall_cap=now.checked_add(std::time::Duration::from_millis(data.valid_until_ms-wall)).ok_or_else(||rejected("financial signing service bound overflow"))?;
        // Actual source captures this once before Display. It is retained exact;
        // wire flooring and original source/session minima may only shorten it.
        let service_ceiling=frozen_service_ceiling(original_service_deadline,setup.source_ceiling,wall_cap);
        require_time(service_ceiling)?;
        let service_ceiling_ms=self.core.clocks.restrictive_offset(service_ceiling,setup.source_ceiling)?;
        let review_ceiling=setup.setup_ceiling.min(service_ceiling).min(wall_ceiling(now,wall,data.prepared_at_ms,data.expires_at_ms)?);
        let b=Arc::new(ReviewBinding{setup:Arc::clone(setup),data:data.clone(),challenge:state::nonce()?,original_service:original_service_deadline,
            service_ceiling,review_ceiling,last_wall:AtomicU64::new(wall)});
        b.review_current()?;self.core.step(SETUP,REVIEW)?;self.review=Some(Arc::clone(&b));
        self.send(&Packet::Display{setup_challenge:setup.wire.setup_challenge.clone(),witness_instance:self.instance.clone(),serve_challenge:b.challenge.clone(),service_ceiling_ms,data})
    }
    /// The actual worker has accepted its genuine Serve and retained the bounded
    /// listener/service before this acknowledgement. No public DTO can create it.
    pub fn acknowledge_serving(&mut self) -> Result<()> {
        if self.serving_ack || self.core.phase.load(Ordering::Acquire) != SERVING {
            return Err(rejected("financial signing Serving repeated"));
        }
        let b = self
            .review
            .as_ref()
            .ok_or_else(|| rejected("financial signing review missing"))?;
        b.service_current()?;
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
            return Err(rejected("financial signing preparation failure phase"));
        }
        self.core.restrict();
        self.failed = true;
        self.first_cleanup()?;
        let setup = self
            .setup
            .as_ref()
            .ok_or_else(|| rejected("financial signing failure before Setup"))?;
        self.send(&Packet::PreparationFailed {
            setup_challenge: setup.wire.setup_challenge.clone(),
        })
    }
    pub fn send_service_failed(&mut self) -> Result<()> {
        if self.failed || self.disposed {
            return Err(rejected("financial signing service failure repeated"));
        }
        self.core.restrict();
        self.failed = true;
        self.first_cleanup()?;
        let b = self
            .review
            .as_ref()
            .ok_or_else(|| rejected("financial signing failure before review"))?;
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
            return Err(rejected("financial signing disposal phase"));
        }
        self.first_cleanup()?;
        let cleanup_ceiling_ms = self
            .core
            .clocks
            .cleanup_offset(self.original_cleanup_deadline()?)?;
        let (c, s) = self
            .coordinator
            .as_ref()
            .ok_or_else(|| rejected("financial signing disposal identity"))?;
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
            return Err(rejected("financial signing grammar not closed"));
        }
        let (c, s) = self
            .coordinator
            .as_ref()
            .ok_or_else(|| rejected("financial signing close identity"))?;
        self.send(&Packet::PurposeClosed {
            coordinator: c.clone(),
            session: s.clone(),
        })?;
        self.closed = true;
        Ok(())
    }
    pub fn complete(mut self, work: Result<()>) -> ! {
        let result = (|| {
            work?;
            if !self.disposed || !self.closed {
                return Err(rejected("financial signing terminal handshake incomplete"));
            }
            let leaf = self
                .leaf
                .take()
                .ok_or_else(|| rejected("financial signing custody consumed"))?;
            bootstrap::finish_leaf_capped(leaf, Ok(()), self.cleanup)
        })();
        self.core.close();
        bootstrap::child_exit(result)
    }
}
impl Drop for WitnessFinancialSigningOriginV1 {
    fn drop(&mut self) {
        self.core.close();
    }
}

fn frozen_service_ceiling(original:Instant,source:Instant,wall_cap:Instant)->Instant{original.min(source).min(wall_cap)}
#[cfg(test)]mod tests{use super::*;
#[test]fn signing_service_clock_never_renews_and_has_no_completed_setup_ancestor(){
 let epoch=Instant::now();let source=epoch+std::time::Duration::from_secs(500);let actual=epoch+std::time::Duration::from_secs(400);
 let setup=epoch+std::time::Duration::from_secs(120);let wall=epoch+std::time::Duration::from_secs(450);
 let retained=frozen_service_ceiling(actual,source,wall);assert_eq!(retained,actual);assert!(retained>setup);
 assert_eq!(frozen_service_ceiling(actual,source,epoch+std::time::Duration::from_secs(350)),epoch+std::time::Duration::from_secs(350));
}
}
