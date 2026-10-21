//! Genuine Continue-only C -> trusted H -> original S custody. No command or
//! native controller activates this feature yet. Whole pinned-image code is
//! trusted; source facts are independently matched by the Signer's source owner.
use crate::{bootstrap::{self, InertTreeV1, LeafCustody, PhaseDeadlinesV1}, image::VerifiedCommonImageIdentity,
    process::PeerLifetime, rejected, Result, HostOriginV1};
use super::{signer_continue_channel::{Binding, Context, Packet, SignerContinueRoleV1 as Target,
    SignerContinueSourceFactsV1, SignerContinueReviewDataV1, SignerContinuePresentationV1, SignerContinueOutcomeV1},
    signer_continue_state::{self as state, Core, Phases, NEW, PREPARING, REVIEW, ARMED, READY, ADMITTED, PENDING, SENT, ABANDONED}};
use std::{marker::PhantomData, rc::Rc, sync::{Arc, atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering}}, time::{Duration, Instant}};

pub(super) struct SignerBirthContext {
    pub(super) coordinator: PeerLifetime, pub(super) image: VerifiedCommonImageIdentity,
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(super) restriction: crate::host_restriction::SignerSharedRestrictionV1,
}
struct Reviewed {
    core: Arc<Core>, wire: Binding,
    original_source: Instant, original_review: Instant, ceiling: Instant,
    last_wall: AtomicU64,
}
impl Reviewed {
    fn check(&self, allow_revoked: bool) -> Result<()> {
        self.core.check()?;
        let now = Instant::now(); let wall = state::wall_ms()?;
        let r = &self.wire.presentation.review;
        let last = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if (!allow_revoked && self.core.phase.revoked()) || now >= self.ceiling
            || now >= self.original_source || now >= self.original_review || now >= self.core.session
            || wall < last || wall < r.reviewed_at_ms || wall >= r.expires_at_ms || wall >= r.session_expires_at_ms
        { self.core.phase.revoke(); return Err(rejected("original Continue review no longer current")); }
        Ok(())
    }
    fn slot(&self) -> usize { self.wire.context.role.index() }
    fn matches(&self, context: &Context, p: &str, e: &str) -> bool {
        context == &self.wire.context && p == self.wire.presentation.presentation_digest && e == self.wire.presentation.prepared_digest
    }
}
struct ReadyBinding { review: Arc<Reviewed>, challenge: String }
pub struct SignerContinueReviewTicketV1 { binding: Arc<Reviewed>, consumed: bool }
pub struct SignerContinueReadyTicketV1 { binding: Arc<ReadyBinding>, consumed: bool }
pub struct SignerContinueArmOutboundV1 { binding: Arc<Reviewed>, consumed: bool }
pub struct SignerContinueFinalOutboundV1 { binding: Arc<ReadyBinding>, consumed: bool }
impl SignerContinueReviewTicketV1 { pub fn presentation(&self) -> &SignerContinuePresentationV1 { &self.binding.wire.presentation } }
impl SignerContinueReadyTicketV1 { pub fn presentation(&self) -> &SignerContinuePresentationV1 { &self.binding.review.wire.presentation } }
impl Drop for SignerContinueReviewTicketV1 { fn drop(&mut self) { if !self.consumed { self.binding.core.phase.revoke(); } } }
impl Drop for SignerContinueReadyTicketV1 { fn drop(&mut self) { if !self.consumed { self.binding.review.core.phase.revoke(); } } }
impl Drop for SignerContinueArmOutboundV1 { fn drop(&mut self) { if !self.consumed { self.binding.core.phase.revoke(); } } }
impl Drop for SignerContinueFinalOutboundV1 { fn drop(&mut self) { if !self.consumed {
    self.binding.review.core.outbound[self.binding.review.slot()].compare_exchange(PENDING, ABANDONED, Ordering::AcqRel, Ordering::Acquire).ok();
    self.binding.review.core.phase.revoke();
} } }

/// Only the reviewed native event-loop thread owns this issuer. Arm is a human
/// conditional gesture; A is the later visible-tail CAS consuming exact Ready.
pub struct CoordinatorSignerContinueNativeV1 { core: Arc<Core>, _thread: PhantomData<Rc<()>> }
impl CoordinatorSignerContinueNativeV1 {
    pub fn revoke(&self) { self.core.phase.revoke(); }
    pub fn is_revoked(&self) -> bool { self.core.phase.revoked() }
    pub fn arm(&self, mut ticket: SignerContinueReviewTicketV1) -> Result<SignerContinueArmOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.core) { self.revoke(); return Err(rejected("foreign Continue review")); }
        ticket.binding.check(false)?;
        self.core.phase.step(ticket.binding.slot(), REVIEW, ARMED)?;
        ticket.consumed = true;
        Ok(SignerContinueArmOutboundV1 { binding: Arc::clone(&ticket.binding), consumed: false })
    }
    pub fn admit(&self, mut ticket: SignerContinueReadyTicketV1) -> Result<SignerContinueFinalOutboundV1> {
        let review = &ticket.binding.review;
        if !Arc::ptr_eq(&self.core, &review.core) { self.revoke(); return Err(rejected("foreign Continue Ready")); }
        review.check(false)?;
        // A and global R are ordered by this same atomic word, across both S slots.
        self.core.phase.step(review.slot(), READY, ADMITTED)?;
        ticket.consumed = true;
        Ok(SignerContinueFinalOutboundV1 { binding: Arc::clone(&ticket.binding), consumed: false })
    }
}
impl Drop for CoordinatorSignerContinueNativeV1 { fn drop(&mut self) { self.revoke(); } }

pub enum CoordinatorSignerContinueEventV1 {
    Display(SignerContinueReviewTicketV1), Ready(SignerContinueReadyTicketV1),
    Outcome { role: Target, data: SignerContinueOutcomeV1 }, PreparationFailed(Target), Disposed(Target),
    /// Authenticated stale display/Ready was discarded after permanent R.
    Restricted(Target),
}
struct CSlot { context: Context, native_ceiling: Instant, review: Option<Arc<Reviewed>>, ready: Option<Arc<ReadyBinding>>, terminal: bool }
pub struct CoordinatorSignerContinueEndpointV1 {
    core: Arc<Core>, tree: Option<InertTreeV1>, coordinator: String,
    slots: [Option<CSlot>; 2], disposed: [bool; 2], cancel_sent: bool, cleanup: Option<Instant>,
}
pub(super) fn split_coordinator(tree: InertTreeV1, clocks: PhaseDeadlinesV1) -> Result<(CoordinatorSignerContinueNativeV1, CoordinatorSignerContinueEndpointV1)> {
    let core = Arc::new(Core {retired_roots:std::sync::atomic::AtomicU32::new(0), phase: Phases::new(),
        #[cfg(feature="coordinated-financial-workflow-v1")]
        witness_outbound: [AtomicU8::new(PENDING),AtomicU8::new(PENDING)],
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        signer_restriction: None,
        peer: tree.continue_host()?.continue_observer()?, roots: tree.continue_pidfds()?,
        coordinator: None, owner_pid: unsafe {libc::getpid()}, owner_uid: unsafe {libc::geteuid()}, epoch: clocks.epoch(), session: clocks.session,
        alive: AtomicBool::new(true), outbound: [AtomicU8::new(PENDING), AtomicU8::new(PENDING)] });
    core.check()?;
    let coordinator = state::nonce()?;
    Ok((CoordinatorSignerContinueNativeV1 { core: Arc::clone(&core), _thread: PhantomData },
        CoordinatorSignerContinueEndpointV1 { core, tree: Some(tree), coordinator, slots: [None,None], disposed:[false;2], cancel_sent:false, cleanup:None }))
}
impl CoordinatorSignerContinueEndpointV1 {
    pub fn session_deadline(&self) -> Instant { self.core.session }
    pub fn check_original_tree_alive(&self) -> Result<()> { self.core.check() }
    pub fn begin_signer1(&mut self, original_native_ceiling: Instant) -> Result<()> { self.begin(Target::Signer1, original_native_ceiling) }
    pub fn begin_signer2(&mut self, original_native_ceiling: Instant) -> Result<()> { self.begin(Target::Signer2, original_native_ceiling) }
    fn send(&self, packet: &Packet) -> Result<()> {
        crate::channel::require_time(self.cleanup.unwrap_or(self.core.session+Duration::from_secs(5)))?;
        self.core.check()?;
        let result = self.tree.as_ref().ok_or_else(|| rejected("Continue tree consumed"))?.continue_host()?.continue_send(packet);
        if result.is_err() { self.core.close(); } result
    }
    fn begin(&mut self, target: Target, original: Instant) -> Result<()> {
        let i = target.index(); self.core.phase.step(i, NEW, PREPARING)?;
        let now = Instant::now(); let ceiling = original.min(self.core.session).min(now + Duration::from_secs(120));
        if ceiling <= now { self.core.phase.revoke(); return Err(rejected("queued Continue prepare expired")); }
        let context = Context { coordinator: self.coordinator.clone(), role: target, slot_challenge: state::nonce()?, native_deadline_ms: state::deadline_offset(self.core.epoch, ceiling)? };
        self.slots[i] = Some(CSlot { context:context.clone(), native_ceiling:ceiling, review:None, ready:None, terminal:false });
        self.send(&Packet::PrepareOnce {context})
    }
    pub fn send_arm(&mut self, mut grant: SignerContinueArmOutboundV1) -> Result<()> {
        let b = &grant.binding; let i = b.slot();
        if !Arc::ptr_eq(&b.core,&self.core) || self.slots[i].as_ref().and_then(|s|s.review.as_ref()).is_none_or(|r|!Arc::ptr_eq(r,b))
            || self.core.phase.phase(i) != ARMED { self.core.close(); return Err(rejected("foreign or repeated Continue Arm")); }
        b.check(false)?; grant.consumed = true;
        self.send(&Packet::Arm {context:b.wire.context.clone(),presentation_digest:b.wire.presentation.presentation_digest.clone(),prepared_digest:b.wire.presentation.prepared_digest.clone()})
    }
    pub fn send_final(&mut self, mut grant: SignerContinueFinalOutboundV1) -> Result<()> {
        let ready = &grant.binding; let b = &ready.review; let i = b.slot();
        if !Arc::ptr_eq(&b.core,&self.core) || self.slots[i].as_ref().and_then(|s|s.ready.as_ref()).is_none_or(|r|!Arc::ptr_eq(r,ready)) || self.core.phase.phase(i) != ADMITTED {
            self.core.close(); return Err(rejected("foreign or repeated Continue final")); }
        // A-before-R survives. This is transport only, never a new admission.
        b.check(true)?;
        self.core.outbound[i].compare_exchange(PENDING,SENT,Ordering::AcqRel,Ordering::Acquire).map_err(|_|rejected("Continue final already consumed"))?;
        grant.consumed = true;
        self.send(&Packet::Final {context:b.wire.context.clone(),presentation_digest:b.wire.presentation.presentation_digest.clone(),prepared_digest:b.wire.presentation.prepared_digest.clone(),ready_challenge:ready.challenge.clone()})
    }
    pub fn send_cancel(&mut self) -> Result<()> {
        self.core.phase.revoke();
        if self.core.pending() { return Err(rejected("admitted Continue final must precede Cancel")); }
        if self.cancel_sent { return Err(rejected("Continue Cancel already consumed")); }
        self.cancel_sent = true;
        self.cleanup = Some((Instant::now()+Duration::from_secs(5)).min(self.core.session+Duration::from_secs(5)));
        self.send(&Packet::Cancel {coordinator:self.coordinator.clone()})
    }
    pub fn try_receive(&mut self) -> Result<Option<CoordinatorSignerContinueEventV1>> {
        crate::channel::require_time(self.cleanup.unwrap_or(self.core.session+Duration::from_secs(5)))?;
        self.core.check()?;
        let result = self.receive_inner(); if result.is_err() { self.core.close(); } result
    }
    fn receive_inner(&mut self) -> Result<Option<CoordinatorSignerContinueEventV1>> {
        let Some(packet) = self.tree.as_ref().ok_or_else(||rejected("Continue tree consumed"))?.continue_host()?.continue_receive()? else {return Ok(None)};
        let event = match packet {
            Packet::Disposed {coordinator,role} => { let i=role.index(); if coordinator!=self.coordinator || self.disposed[i] {return Err(rejected("Continue duplicate disposal"));}
                if let Some(s)=&self.slots[i] { if (s.review.is_some() && !s.terminal) || (!s.terminal && !self.cancel_sent) {return Err(rejected("Continue disposal before outcome"));} }
                else if !self.cancel_sent {return Err(rejected("unsolicited Continue disposal"));}
                self.disposed[i]=true; CoordinatorSignerContinueEventV1::Disposed(role) }
            Packet::Display {binding} => {
                binding.validate()?; let i=binding.context.role.index(); let slot=self.slots[i].as_mut().ok_or_else(||rejected("unsolicited Continue display"))?;
                if slot.context!=binding.context || slot.review.is_some() || slot.terminal || self.core.phase.phase(i)!=PREPARING {return Err(rejected("Continue display binding"));}
                let now=Instant::now(); let source=state::original_deadline(self.core.epoch,binding.source_deadline_ms,self.core.session,now)?;
                let review=state::original_deadline(self.core.epoch,binding.review_deadline_ms,slot.native_ceiling,now)?;
                let b=Arc::new(Reviewed {core:Arc::clone(&self.core),wire:binding,original_source:source,original_review:review,ceiling:source.min(review).min(slot.native_ceiling),last_wall:AtomicU64::new(0)});
                slot.review=Some(Arc::clone(&b));
                if self.core.phase.revoked() { CoordinatorSignerContinueEventV1::Restricted(b.wire.context.role) }
                else { b.check(false)?; self.core.phase.step(i,PREPARING,REVIEW)?;
                    CoordinatorSignerContinueEventV1::Display(SignerContinueReviewTicketV1 {binding:b,consumed:false}) }
            }
            Packet::Ready {context,presentation_digest,prepared_digest,ready_challenge} => {
                let i=context.role.index(); let slot=self.slots[i].as_mut().ok_or_else(||rejected("unsolicited Continue Ready"))?;
                let b=slot.review.as_ref().ok_or_else(||rejected("Continue Ready before display"))?;
                if !b.matches(&context,&presentation_digest,&prepared_digest) || !state::hash(&ready_challenge) || slot.ready.is_some() || slot.terminal || self.core.phase.phase(i)!=ARMED {return Err(rejected("Continue Ready mismatch"));}
                let ready=Arc::new(ReadyBinding {review:Arc::clone(b),challenge:ready_challenge}); slot.ready=Some(Arc::clone(&ready));
                if self.core.phase.revoked() { CoordinatorSignerContinueEventV1::Restricted(context.role) }
                else { b.check(false)?; self.core.phase.step(i,ARMED,READY)?;
                    CoordinatorSignerContinueEventV1::Ready(SignerContinueReadyTicketV1 {binding:ready,consumed:false}) }
            }
            Packet::Outcome {context,data} => {
                let i=context.role.index(); let slot=self.slots[i].as_mut().ok_or_else(||rejected("unsolicited Continue outcome"))?;
                let b=slot.review.as_ref().ok_or_else(||rejected("Continue outcome without review"))?;
                if context!=slot.context || !data.matches(&b.wire.presentation) || slot.terminal
                    || (matches!(data,SignerContinueOutcomeV1::Continued{..}) && (self.core.phase.phase(i)!=ADMITTED || self.core.outbound[i].load(Ordering::Acquire)!=SENT)) {return Err(rejected("Continue outcome mismatch"));}
                slot.terminal=true; CoordinatorSignerContinueEventV1::Outcome {role:context.role,data}
            }
            Packet::PreparationFailed {context} => {let slot=self.slots[context.role.index()].as_mut().ok_or_else(||rejected("unsolicited Continue preparation failure"))?;
                if context!=slot.context || slot.review.is_some() || slot.terminal {return Err(rejected("Continue preparation failure phase"));} slot.terminal=true;
                self.core.phase.revoke(); CoordinatorSignerContinueEventV1::PreparationFailed(context.role) }
            _ => return Err(rejected("wrong Continue response")),
        }; Ok(Some(event))
    }
    pub fn stop_and_reap(mut self, deadline: Instant) -> Result<()> {
        if !self.cancel_sent || self.disposed != [true;2] { return Err(rejected("Continue disposal not confirmed")); }
        let bound=deadline.min(self.cleanup.ok_or_else(||rejected("Continue cleanup missing"))?).min(self.core.session+Duration::from_secs(5));
        self.core.alive.store(false,Ordering::Release); self.core.phase.revoke();
        let result=self.tree.take().ok_or_else(||rejected("Continue tree consumed"))?.stop_and_reap(bound);
        self.core.close(); result
    }
}
impl Drop for CoordinatorSignerContinueEndpointV1 { fn drop(&mut self) { self.core.close(); } }

pub enum SignerContinueRequestV1 { PrepareOnce, Arm(SignerContinueArmV1), Final(SignerContinueFinalV1), Cancel }
/// Inert same-ticket recheck permission, not a mutation issuer.
pub struct SignerContinueArmV1 { binding: TokenBinding }
/// Single-use actual received final grant. Only this module's authenticated
/// original H receive constructs it; the Signer effect entry must consume it.
pub struct SignerContinueFinalV1 { binding: TokenBinding, ready_challenge: String }
enum TokenBinding {
    Narrow(Arc<Reviewed>),
    #[cfg(feature="coordinated-financial-workflow-v1")]
    RetainedWorkflow(Arc<crate::financial_workflow_continue::FullContinueReviewed>),
}
impl TokenBinding {
    fn presentation(&self)->&SignerContinuePresentationV1{match self{Self::Narrow(b)=>&b.wire.presentation,
        #[cfg(feature="coordinated-financial-workflow-v1")] Self::RetainedWorkflow(b)=>&b.wire.presentation}}
    fn source(&self)->Instant{match self{Self::Narrow(b)=>b.original_source,
        #[cfg(feature="coordinated-financial-workflow-v1")] Self::RetainedWorkflow(b)=>b.original_source()}}
    fn review_deadline(&self)->Instant{match self{Self::Narrow(b)=>b.original_review,
        #[cfg(feature="coordinated-financial-workflow-v1")] Self::RetainedWorkflow(b)=>b.original_review}}
}

macro_rules! token_readers {
    ($ty:ty) => { impl $ty {
        pub fn review(&self) -> &SignerContinueReviewDataV1 { &self.binding.presentation().review }
        pub fn presentation_digest(&self) -> &str { &self.binding.presentation().presentation_digest }
        pub fn prepared_digest(&self) -> &str { &self.binding.presentation().prepared_digest }
        pub fn original_source_deadline(&self) -> Instant { self.binding.source() }
        pub fn original_review_deadline(&self) -> Instant { self.binding.review_deadline() }
    } };
}
token_readers!(SignerContinueArmV1); token_readers!(SignerContinueFinalV1);
impl SignerContinueArmV1 {
    pub fn check_current(&self)->Result<()>{match &self.binding{
        TokenBinding::Narrow(b)=>{b.check(false)?;if b.core.phase.phase(b.slot())!=ARMED{return Err(rejected("Continue Arm consumed"));}Ok(())},
        #[cfg(feature="coordinated-financial-workflow-v1")]
        TokenBinding::RetainedWorkflow(b)=>b.check_arm(),
    }}
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn from_retained_workflow(binding:Arc<crate::financial_workflow_continue::FullContinueReviewed>)->Self{Self{binding:TokenBinding::RetainedWorkflow(binding)}}
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn matches_retained_workflow(&self,b:&Arc<crate::financial_workflow_continue::FullContinueReviewed>)->bool{
        matches!(&self.binding,TokenBinding::RetainedWorkflow(actual) if Arc::ptr_eq(actual,b))
    }
}
impl SignerContinueFinalV1 {
    pub fn check_current(&self)->Result<()>{
        match &self.binding{
            TokenBinding::Narrow(b)=>{b.check(true)?;if b.core.phase.phase(b.slot())!=ADMITTED||!state::hash(&self.ready_challenge){return Err(rejected("Continue final phase lost"));}Ok(())},
            #[cfg(feature="coordinated-financial-workflow-v1")]
            TokenBinding::RetainedWorkflow(b)=>{b.check_final()?;if !state::hash(&self.ready_challenge){return Err(rejected("full Continue final challenge lost"));}Ok(())},
        }
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn from_retained_workflow(binding:Arc<crate::financial_workflow_continue::FullContinueReviewed>,ready_challenge:String)->Self{
        Self{binding:TokenBinding::RetainedWorkflow(binding),ready_challenge}
    }
}
struct Draft { review: SignerContinueReviewDataV1, source: Instant, review_deadline: Instant, ceiling: Instant }
pub struct SignerFinancialOriginV1 {
    core: Arc<Core>, leaf: Option<LeafCustody>, target: Target, instance: String, image: String,
    context: Option<Context>, draft: Option<Draft>, reviewed: Option<Arc<Reviewed>>, ready: Option<String>,
    cancel_seen: bool, terminal: bool, disposed: bool, review_started: bool, cleanup:Option<Instant>,
}
impl SignerFinancialOriginV1 {
    pub(super) fn from_signer(leaf: LeafCustody, birth: SignerBirthContext) -> Result<Self> {
        let target=Target::from_role(leaf.origin.role())?;
        let core=Arc::new(Core {retired_roots:std::sync::atomic::AtomicU32::new(0),phase:Phases::new(),
            #[cfg(feature="coordinated-financial-workflow-v1")]
            witness_outbound: [AtomicU8::new(PENDING),AtomicU8::new(PENDING)],
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            signer_restriction: Some(birth.restriction),
            peer:leaf.origin.continue_observer()?,roots:Vec::new(),coordinator:Some(birth.coordinator),
            owner_pid:unsafe{libc::getpid()},owner_uid:unsafe{libc::geteuid()},epoch:leaf.clocks.epoch(),session:leaf.clocks.session,
            alive:AtomicBool::new(true),outbound:[AtomicU8::new(PENDING),AtomicU8::new(PENDING)]});
        core.check()?;
        Ok(Self {core,leaf:Some(leaf),target,instance:state::nonce()?,image:birth.image.measurement().to_owned(),context:None,draft:None,reviewed:None,ready:None,cancel_seen:false,terminal:false,disposed:false,review_started:false,cleanup:None})
    }
    pub fn session_deadline(&self) -> Instant {self.core.session}
    pub fn check_original_actors_alive(&self) -> Result<()> {self.core.check()}
    fn send(&self, packet:&Packet) -> Result<()> {
        crate::channel::require_time(self.cleanup.unwrap_or(self.core.session+Duration::from_secs(5)))?;
        self.core.check()?;
        let result=self.leaf.as_ref().ok_or_else(||rejected("Continue Signer custody consumed"))?.origin.continue_send(packet);
        if result.is_err(){self.core.close();} result
    }
    pub fn try_receive(&mut self) -> Result<Option<SignerContinueRequestV1>> {
        crate::channel::require_time(self.cleanup.unwrap_or(self.core.session+Duration::from_secs(5)))?;
        self.core.check()?;
        let result=self.receive_inner(); if result.is_err(){self.core.close();} result
    }
    fn receive_inner(&mut self) -> Result<Option<SignerContinueRequestV1>> {
        let Some(packet)=self.leaf.as_ref().ok_or_else(||rejected("Continue Signer custody consumed"))?.origin.continue_receive()? else{return Ok(None)};
        let request=match packet {
            Packet::PrepareOnce{context} => {
                context.validate()?;
                if context.role!=self.target || self.context.is_some() || self.cancel_seen || self.disposed {return Err(rejected("Continue Signer slot already consumed"));}
                state::original_deadline(self.core.epoch,context.native_deadline_ms,self.core.session,Instant::now())?;
                self.core.phase.step(self.target.index(),NEW,PREPARING)?; self.context=Some(context); SignerContinueRequestV1::PrepareOnce
            }
            Packet::Arm{context,presentation_digest,prepared_digest} => {
                let b=self.reviewed.as_ref().ok_or_else(||rejected("Continue Arm before display"))?;
                if !b.matches(&context,&presentation_digest,&prepared_digest) || self.terminal {return Err(rejected("Continue Arm mismatch"));}
                b.check(false)?; self.core.phase.step(self.target.index(),REVIEW,ARMED)?;
                SignerContinueRequestV1::Arm(SignerContinueArmV1{binding:TokenBinding::Narrow(Arc::clone(b))})
            }
            Packet::Final{context,presentation_digest,prepared_digest,ready_challenge} => {
                let b=self.reviewed.as_ref().ok_or_else(||rejected("Continue final before review"))?;
                if !b.matches(&context,&presentation_digest,&prepared_digest) || self.ready.as_ref()!=Some(&ready_challenge) || self.terminal {return Err(rejected("Continue final mismatch"));}
                b.check(false)?; self.core.phase.step(self.target.index(),READY,ADMITTED)?;
                SignerContinueRequestV1::Final(SignerContinueFinalV1{binding:TokenBinding::Narrow(Arc::clone(b)),ready_challenge})
            }
            Packet::Cancel{coordinator} => {
                if !state::hash(&coordinator) || self.cancel_seen || self.context.as_ref().is_some_and(|c|c.coordinator!=coordinator) {return Err(rejected("Continue Cancel mismatch"));}
                // The ordered Final, if received first, remains ADMITTED. Global R
                // restricts all future Arm/A; retained original deaths still deny.
                self.core.phase.revoke(); self.cancel_seen=true;
                self.cleanup=Some((Instant::now()+Duration::from_secs(5)).min(self.core.session+Duration::from_secs(5)));
                if self.context.is_none(){self.context=Some(Context{coordinator,role:self.target,slot_challenge:String::new(),native_deadline_ms:0});}
                SignerContinueRequestV1::Cancel
            }
            _ => return Err(rejected("wrong Continue Signer request")),
        }; Ok(Some(request))
    }
    /// This fills only genuine origin-held facts. It does not authenticate the
    /// caller's source data or open a source. The actual Signer preparation must
    /// independently match its retained source/history and protected Host peer.
    pub fn begin_review(&mut self, facts: SignerContinueSourceFactsV1, original_source_deadline:Instant, original_review_deadline:Instant) -> Result<SignerContinueReviewDataV1> {
        if std::mem::replace(&mut self.review_started,true) {self.core.phase.revoke();return Err(rejected("Continue review already attempted"));}
        self.core.check()?;
        if self.core.phase.phase(self.target.index())!=PREPARING || self.core.phase.revoked() || self.draft.is_some(){return Err(rejected("Continue review already consumed"));}
        let context=self.context.as_ref().ok_or_else(||rejected("Continue prepare missing"))?;
        let now=Instant::now(); let native=state::original_deadline(self.core.epoch,context.native_deadline_ms,self.core.session,now)?;
        let ceiling=original_source_deadline.min(original_review_deadline).min(native).min(self.core.session);
        if ceiling<=now {self.core.phase.revoke();return Err(rejected("Continue original source/review expired"));}
        let review=SignerContinueReviewDataV1 {coordinator_process_instance:context.coordinator.clone(),coordinator_focus_epoch:1,signer_role:self.target,
            signer_process_instance:self.instance.clone(),original_host_process_instance:facts.original_host_process_instance,signer_principal_id:facts.signer_principal_id,
            signer_image_measurement:self.image.clone(),source_identity_digest:facts.source_identity_digest,terms_digest:facts.terms_digest,session_digest:facts.session_digest,
            review_challenge:state::nonce()?,review_digest:facts.review_digest,reviewed_at_ms:facts.reviewed_at_ms,expires_at_ms:facts.expires_at_ms,session_expires_at_ms:facts.session_expires_at_ms};
        review.validate()?; let wall=state::wall_ms()?;
        if wall<review.reviewed_at_ms || wall>=review.expires_at_ms {self.core.phase.revoke();return Err(rejected("Continue original wall bounds expired"));}
        self.draft=Some(Draft{review:review.clone(),source:original_source_deadline,review_deadline:original_review_deadline,ceiling}); Ok(review)
    }
    pub fn send_display(&mut self, data:SignerContinuePresentationV1) -> Result<()> {
        let draft=self.draft.take().ok_or_else(||rejected("Continue source review missing"))?;
        if let Err(error)=data.validate(){self.core.phase.revoke();return Err(error);}
        if data.review!=draft.review || self.reviewed.is_some() || self.terminal {self.core.phase.revoke();return Err(rejected("Continue source display mismatch"));}
        let binding=Binding {context:self.context.clone().ok_or_else(||rejected("Continue context missing"))?,presentation:data,
            source_deadline_ms:state::deadline_offset(self.core.epoch,draft.source.min(self.core.session))?,review_deadline_ms:state::deadline_offset(self.core.epoch,draft.review_deadline.min(self.core.session))?};
        binding.validate()?;
        let b=Arc::new(Reviewed {core:Arc::clone(&self.core),wire:binding,original_source:draft.source,original_review:draft.review_deadline,ceiling:draft.ceiling,last_wall:AtomicU64::new(0)});
        b.check(false)?; self.core.phase.step(self.target.index(),PREPARING,REVIEW)?;
        self.reviewed=Some(Arc::clone(&b)); self.send(&Packet::Display{binding:b.wire.clone()})
    }
    /// Consumes the genuine inert Arm only after the actual source has rechecked
    /// its same frozen ticket and dropped every source/journal guard.
    pub fn send_ready(&mut self, arm:SignerContinueArmV1) -> Result<()> {
        let b=self.reviewed.as_ref().ok_or_else(||rejected("Continue review missing"))?;
        if !matches!(&arm.binding,TokenBinding::Narrow(actual) if Arc::ptr_eq(b,actual)) || self.ready.is_some() || self.terminal {return Err(rejected("foreign Continue Arm"));}
        arm.check_current()?; let challenge=state::nonce()?;
        self.core.phase.step(self.target.index(),ARMED,READY)?; self.ready=Some(challenge.clone());
        self.send(&Packet::Ready{context:b.wire.context.clone(),presentation_digest:b.wire.presentation.presentation_digest.clone(),prepared_digest:b.wire.presentation.prepared_digest.clone(),ready_challenge:challenge})
    }
    pub fn send_preparation_failed(&mut self) -> Result<()> {
        if self.reviewed.is_some() || self.terminal || self.cancel_seen {return Err(rejected("Continue preparation failure phase"));}
        let context=self.context.clone().ok_or_else(||rejected("Continue prepare missing"))?;
        self.terminal=true; self.core.phase.revoke(); self.send(&Packet::PreparationFailed{context})
    }
    pub fn send_outcome(&mut self, data:SignerContinueOutcomeV1) -> Result<()> {
        let b=self.reviewed.as_ref().ok_or_else(||rejected("Continue outcome without display"))?;
        if self.terminal || !data.matches(&b.wire.presentation) || (matches!(data,SignerContinueOutcomeV1::Continued{..}) && self.core.phase.phase(self.target.index())!=ADMITTED) {return Err(rejected("Continue outcome binding"));}
        self.terminal=true; self.send(&Packet::Outcome{context:b.wire.context.clone(),data})
    }
    /// Observation only: caller must have joined workers and dropped actual
    /// source custody. Process exit is not a successful disposal substitute.
    pub fn send_disposed(&mut self) -> Result<()> {
        if self.disposed || (self.reviewed.is_some() && !self.terminal) || (self.reviewed.is_none() && !self.terminal && !self.cancel_seen) {return Err(rejected("Continue premature disposal"));}
        let coordinator=self.context.as_ref().ok_or_else(||rejected("Continue context missing"))?.coordinator.clone();
        self.disposed=true; self.send(&Packet::Disposed{coordinator,role:self.target})
    }
    pub fn complete(mut self, work:Result<()>) -> ! {
        let work=work.and_then(|()|if self.cancel_seen && self.disposed {Ok(())}else{Err(rejected("Continue terminal Cancel/disposal missing"))});
        self.core.alive.store(false,Ordering::Release); self.core.phase.revoke();
        let result=match self.leaf.take(){Some(leaf)=>bootstrap::finish_leaf_capped(leaf,work,self.cleanup),None=>Err(rejected("Continue Signer custody consumed"))};
        self.core.close(); bootstrap::child_exit(result)
    }
}
impl Drop for SignerFinancialOriginV1 {fn drop(&mut self){self.core.close();}}

struct RelaySlot { context:Context, phase:u8, binding:Option<Binding>, ready:Option<String>, last_wall:u64 }
/// H is explicitly trusted to relay the exact finite payload once. It cannot
/// expose a sender, construct C tickets, invoke native Arm/A, or replace S.
pub struct HostSignerFinancialRelayV1 {
    host:Option<HostOriginV1>, coordinator:Option<String>, slots:[Option<RelaySlot>;2], cancel_seen:bool, disposed:[bool;2], cleanup:Option<Instant>,
}
impl HostSignerFinancialRelayV1 {
    pub(super) fn from_host(host:HostOriginV1) -> Result<Self> {
        host.continue_check()?;
        Ok(Self{host:Some(host),coordinator:None,slots:[None,None],cancel_seen:false,disposed:[false;2],cleanup:None})
    }
    pub fn session_deadline(&self) -> Result<Instant> {Ok(self.host.as_ref().ok_or_else(||rejected("Continue Host consumed"))?.continue_clocks().session)}
    /// At most one C packet and one packet per fixed S edge per call. No retry,
    /// arbitrary forwarding operation, callback, target selector or byte import.
    pub fn pump(&mut self) -> Result<bool> {
        let result=self.pump_inner();
        if result.is_err(){drop(self.host.take());}
        result
    }
    fn pump_inner(&mut self) -> Result<bool> {
        let host=self.host.as_ref().ok_or_else(||rejected("Continue Host consumed"))?;
        crate::channel::require_time(self.cleanup.unwrap_or(host.continue_clocks().session+Duration::from_secs(5)))?;
        host.continue_check_lifetimes()?;
        let mut progress=false;
        if let Some(packet)=self.host.as_ref().unwrap().continue_receive_c()? {
            self.down(&packet)?;
            let host=self.host.as_ref().unwrap();
            if matches!(packet,Packet::Cancel{..}) {
                // Ordered after any already-received Final on BOTH edges. Each
                // original seqpacket send is attempted once, never retried.
                host.continue_child(Target::Signer1)?.continue_send(&packet)?;
                host.continue_child(Target::Signer2)?.continue_send(&packet)?;
            } else {
                host.continue_child(packet.target().ok_or_else(||rejected("Continue target missing"))?)?.continue_send(&packet)?;
            }
            progress=true;
        }
        for target in [Target::Signer1,Target::Signer2] {
            if self.disposed[target.index()] {continue;}
            if let Some(packet)=self.host.as_ref().unwrap().continue_child(target)?.continue_receive()? {
                self.up(target,&packet)?;
                self.host.as_ref().unwrap().continue_send_c(&packet)?; progress=true;
            }
        }
        self.host.as_ref().unwrap().continue_check_lifetimes()?; Ok(progress)
    }
    fn down(&mut self,packet:&Packet) -> Result<()> {
        if let Packet::Cancel{coordinator}=packet {
            if !state::hash(coordinator) || self.cancel_seen || self.coordinator.as_ref().is_some_and(|s|s!=coordinator) {return Err(rejected("Continue relay Cancel mismatch"));}
            self.coordinator=Some(coordinator.clone());self.cancel_seen=true;
            self.cleanup=Some((Instant::now()+Duration::from_secs(5)).min(self.host.as_ref().unwrap().continue_clocks().session+Duration::from_secs(5)));return Ok(());
        }
        if self.cancel_seen{return Err(rejected("Continue relay command after Cancel"));}
        crate::channel::require_time(self.host.as_ref().unwrap().continue_clocks().session)?;
        match packet {
            Packet::PrepareOnce{context} => {
                context.validate()?;let i=context.role.index();
                if self.slots[i].is_some() || self.coordinator.as_ref().is_some_and(|s|s!=&context.coordinator){return Err(rejected("Continue relay preparation replay"));}
                let clocks=self.host.as_ref().unwrap().continue_clocks();state::original_deadline(clocks.epoch(),context.native_deadline_ms,clocks.session,Instant::now())?;
                self.coordinator=Some(context.coordinator.clone());self.slots[i]=Some(RelaySlot{context:context.clone(),phase:PREPARING,binding:None,ready:None,last_wall:0});Ok(())
            }
            Packet::Arm{context,presentation_digest,prepared_digest} => {
                let slot=self.slots[context.role.index()].as_mut().ok_or_else(||rejected("Continue relay Arm before prepare"))?;
                relay_match(slot,context,presentation_digest,prepared_digest,REVIEW)?;relay_current(slot,self.host.as_ref().unwrap().continue_clocks())?;slot.phase=ARMED;Ok(())
            }
            Packet::Final{context,presentation_digest,prepared_digest,ready_challenge} => {
                let slot=self.slots[context.role.index()].as_mut().ok_or_else(||rejected("Continue relay final before prepare"))?;
                relay_match(slot,context,presentation_digest,prepared_digest,READY)?;relay_current(slot,self.host.as_ref().unwrap().continue_clocks())?;
                if slot.ready.as_ref()!=Some(ready_challenge){return Err(rejected("Continue relay final challenge"));}slot.phase=ADMITTED;Ok(())
            }
            _=>Err(rejected("wrong Continue relay command")),
        }
    }
    fn up(&mut self,target:Target,packet:&Packet) -> Result<()> {
        if packet.target()!=Some(target){return Err(rejected("Continue relay original Signer mismatch"));}
        let i=target.index();
        if let Packet::Disposed{coordinator,..}=packet {
            if self.disposed[i] || self.coordinator.as_ref()!=Some(coordinator){return Err(rejected("Continue relay disposal mismatch"));}
            match &self.slots[i] {
                Some(s) if s.binding.is_some() && s.phase!=6 => return Err(rejected("Continue relay disposal before outcome")),
                Some(s) if s.binding.is_none() && s.phase!=6 && !self.cancel_seen => return Err(rejected("Continue relay disposal before terminal")),
                None if !self.cancel_seen => return Err(rejected("Continue relay unsolicited disposal")), _=>(),
            }
            self.disposed[i]=true;return Ok(());
        }
        if matches!(packet,Packet::Display{..}|Packet::Ready{..}) {crate::channel::require_time(self.host.as_ref().unwrap().continue_clocks().session)?;}
        let slot=self.slots[i].as_mut().ok_or_else(||rejected("Continue relay unsolicited response"))?;
        match packet {
            Packet::Display{binding} => {
                binding.validate()?;
                if binding.context!=slot.context || slot.phase!=PREPARING || slot.binding.is_some(){return Err(rejected("Continue relay display mismatch"));}
                let clocks=self.host.as_ref().unwrap().continue_clocks();let now=Instant::now();
                state::original_deadline(clocks.epoch(),binding.source_deadline_ms,clocks.session,now)?;
                state::original_deadline(clocks.epoch(),binding.review_deadline_ms,clocks.session,now)?;
                slot.binding=Some(binding.clone());slot.phase=REVIEW;Ok(())
            }
            Packet::Ready{context,presentation_digest,prepared_digest,ready_challenge}=>{
                relay_match(slot,context,presentation_digest,prepared_digest,ARMED)?;relay_current(slot,self.host.as_ref().unwrap().continue_clocks())?;
                if !state::hash(ready_challenge)||slot.ready.is_some(){return Err(rejected("Continue relay Ready challenge"));}
                slot.ready=Some(ready_challenge.clone());slot.phase=READY;Ok(())
            }
            Packet::Outcome{context,data}=>{
                let b=slot.binding.as_ref().ok_or_else(||rejected("Continue relay outcome before display"))?;
                if context!=&slot.context || slot.phase==6 || !data.matches(&b.presentation)
                    ||(matches!(data,SignerContinueOutcomeV1::Continued{..})&&slot.phase!=ADMITTED){return Err(rejected("Continue relay outcome binding"));}
                slot.phase=6;Ok(())
            }
            Packet::PreparationFailed{context}=>{
                if context!=&slot.context || slot.phase!=PREPARING || slot.binding.is_some(){return Err(rejected("Continue relay preparation failure phase"));}slot.phase=6;Ok(())
            }
            _=>Err(rejected("wrong Continue relay response")),
        }
    }
    pub fn is_disposed(&self) -> bool {self.disposed==[true;2]}
    pub fn complete(mut self, work:Result<()>) -> ! {
        let result=work.and_then(|()|if self.cancel_seen&&self.is_disposed(){Ok(())}else{Err(rejected("Continue relay disposal missing"))})
            .and_then(|()|bootstrap::finish_host_capped(self.host.take().ok_or_else(||rejected("Continue Host consumed"))?,self.cleanup));
        drop(self.host.take());bootstrap::child_exit(result)
    }
}
fn relay_match(slot:&RelaySlot,context:&Context,p:&str,e:&str,phase:u8)->Result<()> {
    let b=slot.binding.as_ref().ok_or_else(||rejected("Continue relay review missing"))?;
    if slot.phase!=phase || context!=&slot.context || p!=b.presentation.presentation_digest || e!=b.presentation.prepared_digest {return Err(rejected("Continue relay exact binding mismatch"));}Ok(())
}

fn relay_current(slot:&mut RelaySlot,clocks:PhaseDeadlinesV1)->Result<()> {
    let b=slot.binding.as_ref().ok_or_else(||rejected("Continue relay binding missing"))?;
    let now=Instant::now();
    state::original_deadline(clocks.epoch(),b.source_deadline_ms,clocks.session,now)?;
    state::original_deadline(clocks.epoch(),b.review_deadline_ms,clocks.session,now)?;
    state::original_deadline(clocks.epoch(),b.context.native_deadline_ms,clocks.session,now)?;
    let wall=state::wall_ms()?;let review=&b.presentation.review;
    if wall<slot.last_wall || wall<review.reviewed_at_ms || wall>=review.expires_at_ms || wall>=review.session_expires_at_ms {return Err(rejected("Continue relay original wall bounds"));}
    slot.last_wall=wall;Ok(())
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn trusted_relay_rejects_reordered_duplicate_and_substituted_final_fields() {
        let binding=super::super::signer_continue_channel::sample_binding();
        let mut slot=RelaySlot{context:binding.context.clone(),phase:READY,binding:Some(binding.clone()),ready:Some("6".repeat(64)),last_wall:0};
        assert!(relay_match(&slot,&binding.context,&binding.presentation.presentation_digest,&binding.presentation.prepared_digest,READY).is_ok());
        assert!(relay_match(&slot,&binding.context,&binding.presentation.presentation_digest,&"7".repeat(64),READY).is_err());
        let mut other=binding.context.clone();other.role=Target::Signer2;
        assert!(relay_match(&slot,&other,&binding.presentation.presentation_digest,&binding.presentation.prepared_digest,READY).is_err());
        slot.phase=ADMITTED;
        assert!(relay_match(&slot,&binding.context,&binding.presentation.presentation_digest,&binding.presentation.prepared_digest,READY).is_err());
    }
    #[test] fn final_before_cancel_requires_sent_or_abandoned_exact_outbound() {
        // Pure state only; no fake Core, process, socket or origin is made.
        let phases=Phases::new();let outbound=AtomicU8::new(PENDING);
        phases.step(0,NEW,READY).unwrap();phases.step(0,READY,ADMITTED).unwrap();phases.revoke();
        assert!(phases.phase(0)==ADMITTED&&outbound.load(Ordering::Acquire)==PENDING);
        outbound.compare_exchange(PENDING,SENT,Ordering::AcqRel,Ordering::Acquire).unwrap();
        assert_ne!(outbound.load(Ordering::Acquire),PENDING);
        assert!(outbound.compare_exchange(PENDING,SENT,Ordering::AcqRel,Ordering::Acquire).is_err());
        let abandoned=AtomicU8::new(PENDING);abandoned.compare_exchange(PENDING,ABANDONED,Ordering::AcqRel,Ordering::Acquire).unwrap();
        assert_ne!(abandoned.load(Ordering::Acquire),PENDING);
    }
}
