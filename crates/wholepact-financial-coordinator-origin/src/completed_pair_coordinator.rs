//! Original C-owned CompletedPair resource service. Ordinary pair data never
//! creates either retired signed custody or a service acknowledgment.
use super::*;
use super::signed_custody::{FinancialSignedResultCustodyV1, SignedResultLease};
use crate::completed_pair_channel::{Packet as CP, Setup};
use crate::completed_pair_data::{CompletedPairInputsV1, CompletedPairOriginalV1, CompletedPairPresentationV1};
use crate::financial_signing_data::FinancialSigningOriginalV1;
use crate::SignerSignCommittedV1;
use std::sync::atomic::AtomicU64;
pub(super) const CP_SETUP: u8 = 1;
pub(super) const CP_ADMITTED: u8 = 2;
pub(super) const CP_REVIEW: u8 = 3;
pub(super) const CP_SERVING: u8 = 4;
pub(super) const CP_DONE: u8 = 5;
struct SetupReview {
    core: Arc<Core>, wire: Setup, members: [SignedResultLease; 2], ceiling: Instant,
    source_deadline: Instant,
}
impl SetupReview {
    fn bounds(&self) -> Result<()> {
        self.core.check()?;
        for member in &self.members { member.check()?; }
        crate::channel::require_time(self.source_deadline)
    }
    fn setup_bounds(&self) -> Result<()> { self.bounds()?; crate::channel::require_time(self.ceiling) }
    fn check(&self) -> Result<()> { self.setup_bounds()?; self.core.check_action_restrictions() }
}
struct Review {
    setup: Arc<SetupReview>, data: CompletedPairPresentationV1, instance: String,
    challenge: String, service_ceiling_ms: u64, service_deadline: Instant,
    review_deadline: Instant, last_wall: AtomicU64,
}
impl Review {
    fn bounds(&self) -> Result<()> {
        self.setup.bounds()?;
        crate::channel::require_time(self.service_deadline)?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old || wall < self.data.valid_from_ms || wall >= self.data.valid_until_ms {
            return Err(rejected("completed pair original service wall clock"));
        }
        Ok(())
    }
    fn current(&self) -> Result<()> { self.bounds()?; self.setup.core.check_action_restrictions() }
    fn review_current(&self) -> Result<()> {
        self.current()?; crate::channel::require_time(self.review_deadline)?;
        if state::wall_ms()? >= self.data.expires_at_ms { return Err(rejected("completed pair review expired")); }
        Ok(())
    }
    fn require_member(&self, core: &Arc<Core>, original: &FinancialSigningOriginalV1, signed: &SignerSignCommittedV1) -> Result<()> {
        self.current()?;
        if !Arc::ptr_eq(core, &self.setup.core) { return Err(rejected("completed pair foreign original Core")); }
        let i = original.actor.signer_role.index();
        if self.data.original.owners[i] != *original { return Err(rejected("completed pair original owner changed")); }
        self.setup.members[i].require_same(core, original, signed)
    }
}
pub struct FinancialCompletedPairSetupTicketV1 { binding: Arc<SetupReview>, consumed: bool }
impl FinancialCompletedPairSetupTicketV1 {
    pub fn inputs(&self) -> &CompletedPairInputsV1 { &self.binding.wire.inputs }
    pub fn original_binding(&self) -> &CompletedPairOriginalV1 { &self.binding.wire.original }
    pub fn native_deadline(&self) -> Instant { self.binding.ceiling }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        if self.binding.core.phase.pair_phase() != CP_SETUP { return Err(rejected("completed pair Setup consumed")); } Ok(())
    }
}
impl Drop for FinancialCompletedPairSetupTicketV1 { fn drop(&mut self) { if !self.consumed { self.binding.core.phase.revoke(); } } }
pub struct FinancialCompletedPairSetupOutboundV1 { binding: Arc<SetupReview>, consumed: bool }
impl Drop for FinancialCompletedPairSetupOutboundV1 { fn drop(&mut self) { if !self.consumed { self.binding.core.phase.revoke(); } } }
pub struct FinancialCompletedPairReviewTicketV1 { binding: Arc<Review>, consumed: bool }
impl FinancialCompletedPairReviewTicketV1 {
    pub fn presentation(&self) -> &CompletedPairPresentationV1 { &self.binding.data }
    pub fn native_deadline(&self) -> Instant { self.binding.review_deadline }
    pub fn check_current(&self) -> Result<()> {
        self.binding.review_current()?;
        if self.binding.setup.core.phase.pair_phase() != CP_REVIEW { return Err(rejected("completed pair review consumed")); } Ok(())
    }
}
impl Drop for FinancialCompletedPairReviewTicketV1 { fn drop(&mut self) { if !self.consumed { self.binding.setup.core.phase.revoke(); } } }
pub struct FinancialCompletedPairServeOutboundV1 { binding: Arc<Review>, consumed: bool }
impl Drop for FinancialCompletedPairServeOutboundV1 { fn drop(&mut self) { if !self.consumed { self.binding.setup.core.phase.revoke(); } } }
/// Only an authenticated acknowledgment from the one original fixed Pair child.
/// No Clone, serde or public constructor. It authorizes no financial operation.
pub struct FinancialCompletedPairServingV1 { binding: Arc<Review> }
impl FinancialCompletedPairServingV1 {
    pub fn presentation(&self) -> &CompletedPairPresentationV1 { &self.binding.data }
    pub fn service_deadline(&self) -> Instant { self.binding.service_deadline }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current()?;
        if self.binding.setup.core.phase.pair_phase() != CP_SERVING { return Err(rejected("completed pair service ended")); } Ok(())
    }
    pub(super) fn retain(&self) -> Result<CompletedPairServiceLease> { self.check_current()?; Ok(CompletedPairServiceLease { binding: Arc::clone(&self.binding) }) }
    pub(super) fn require_member(&self, core: &Arc<Core>, original: &FinancialSigningOriginalV1, signed: &SignerSignCommittedV1) -> Result<()> {
        self.check_current()?; self.binding.require_member(core, original, signed)
    }
}
pub(super) struct CompletedPairServiceLease { binding: Arc<Review> }
impl CompletedPairServiceLease {
    pub(super) fn presentation(&self) -> &CompletedPairPresentationV1 { &self.binding.data }
    pub(super) fn check(&self) -> Result<()> {
        self.binding.current()?;
        if self.binding.setup.core.phase.pair_phase() != CP_SERVING { return Err(rejected("completed pair outbound service ended")); } Ok(())
    }
    pub(super) fn require_member(&self, core: &Arc<Core>, original: &FinancialSigningOriginalV1, signed: &SignerSignCommittedV1) -> Result<()> {
        self.check()?; self.binding.require_member(core, original, signed)
    }
}
pub enum CoordinatorCompletedPairEventV1 {
    Display(FinancialCompletedPairReviewTicketV1), Serving(FinancialCompletedPairServingV1),
    PreparationFailed, ServiceFailed, Disposed, PurposeClosed, Restricted,
}
#[derive(Default)]
pub(super) struct CPState {
    setup: Option<Arc<SetupReview>>, review: Option<Arc<Review>>, wire_phase: u8,
    serving_ack: bool, host_notified: bool, finish_sent: bool, failed: bool,
    cancel_sent: bool, disposed: bool, close_sent: bool, closed: bool, cleanup: Option<Instant>,
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_completed_pair_setup(&self, mut ticket: FinancialCompletedPairSetupTicketV1) -> Result<FinancialCompletedPairSetupOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.core) { self.revoke(); return Err(rejected("completed pair foreign Setup")); }
        ticket.check_current()?; self.core.phase.pair_step(CP_SETUP, CP_ADMITTED)?; ticket.consumed = true;
        Ok(FinancialCompletedPairSetupOutboundV1 { binding: Arc::clone(&ticket.binding), consumed: false })
    }
    pub fn admit_completed_pair_serve(&self, mut ticket: FinancialCompletedPairReviewTicketV1) -> Result<FinancialCompletedPairServeOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.setup.core) { self.revoke(); return Err(rejected("completed pair foreign review")); }
        ticket.check_current()?; self.core.phase.pair_step(CP_REVIEW, CP_SERVING)?; ticket.consumed = true;
        Ok(FinancialCompletedPairServeOutboundV1 { binding: Arc::clone(&ticket.binding), consumed: false })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn prepare_completed_pair_setup(&mut self, inputs: CompletedPairInputsV1, original_native_ceiling: Instant) -> Result<FinancialCompletedPairSetupTicketV1> {
        self.core.check_action_restrictions()?;
        if self.pair_service.setup.is_some() { return Err(rejected("completed pair Setup already selected")); }
        let a: FinancialSignedResultCustodyV1 = self.signed_result_custody(Target::Signer1)?;
        let b: FinancialSignedResultCustodyV1 = self.signed_result_custody(Target::Signer2)?;
        a.check_current()?; b.check_current()?;
        let original = CompletedPairOriginalV1 { owners: [a.original_binding().clone(), b.original_binding().clone()] };
        inputs.require_original(&original)?;
        let now = Instant::now();
        let source_deadline = self.clocks.restrict_received(PROFILE, original.owners[0].source_ceiling_ms, self.clocks.supervision(), now)?
            .min(self.clocks.restrict_received(PROFILE, original.owners[1].source_ceiling_ms, self.clocks.supervision(), now)?);
        let ceiling = original_native_ceiling.min(source_deadline);
        crate::channel::require_time(ceiling)?;
        if ceiling.duration_since(now) > std::time::Duration::from_secs(120) { return Err(rejected("completed pair Setup ceiling too wide")); }
        let wire = Setup { inputs, original, setup_challenge: state::nonce()?, setup_ceiling_ms: self.clocks.restrictive_offset(ceiling, source_deadline)? };
        wire.validate()?;
        let binding = Arc::new(SetupReview { core: Arc::clone(&self.core), wire, members: [a.retain()?, b.retain()?], ceiling, source_deadline });
        binding.check()?; self.core.phase.pair_step(0, CP_SETUP)?;
        self.pair_service.setup = Some(Arc::clone(&binding)); self.pair_service.wire_phase = CP_SETUP;
        Ok(FinancialCompletedPairSetupTicketV1 { binding, consumed: false })
    }
    fn send_pair(&self, packet: &CP) -> Result<()> {
        self.transport_check()?;
        if let Some(c) = self.pair_service.cleanup { crate::channel::require_time(c)?; }
        self.tree.as_ref().ok_or_else(|| rejected("completed pair tree consumed"))?.completed_pair()?.completed_pair_send(packet)
    }
    fn send_pair_positive(&self, packet: &CP, deadline: Instant) -> Result<FinancialSendProgressV1> {
        self.transport_check()?;
        self.tree.as_ref().ok_or_else(|| rejected("completed pair tree consumed"))?.completed_pair()?.completed_pair_send_positive(packet, &self.core.phase, deadline)
    }
    pub fn try_send_completed_pair_setup(&mut self, mut out: FinancialCompletedPairSetupOutboundV1) -> Result<FinancialSendProgressV1> {
        let b = &out.binding;
        if !Arc::ptr_eq(&self.core, &b.core) || self.pair_service.setup.as_ref().is_none_or(|s| !Arc::ptr_eq(s,b)) || self.pair_service.wire_phase != CP_SETUP {
            return Err(rejected("completed pair Setup outbound mismatch"));
        }
        b.setup_bounds()?;
        if self.core.phase.pair_send_restricted(CP_ADMITTED)? { out.consumed = true; return Ok(FinancialSendProgressV1::Restricted); }
        out.consumed = true;
        let result = self.send_pair_positive(&CP::PrepareOnce { setup: b.wire.clone() }, b.ceiling)?;
        if result == FinancialSendProgressV1::Sent { self.pair_service.wire_phase = CP_ADMITTED; }
        Ok(result)
    }
    pub fn try_send_completed_pair_serve(&mut self, mut out: FinancialCompletedPairServeOutboundV1) -> Result<FinancialSendProgressV1> {
        let b = &out.binding;
        if !Arc::ptr_eq(&self.core, &b.setup.core) || self.pair_service.review.as_ref().is_none_or(|s| !Arc::ptr_eq(s,b)) || self.pair_service.wire_phase != CP_REVIEW {
            return Err(rejected("completed pair Serve outbound mismatch"));
        }
        b.review_current()?;
        if self.core.phase.pair_send_restricted(CP_SERVING)? { out.consumed = true; return Ok(FinancialSendProgressV1::Restricted); }
        out.consumed = true;
        let result = self.send_pair_positive(&CP::Serve { setup_challenge:b.setup.wire.setup_challenge.clone(), witness_instance:b.instance.clone(), serve_challenge:b.challenge.clone(), presentation_digest:b.data.presentation_digest.clone() }, b.review_deadline)?;
        if result == FinancialSendProgressV1::Sent { self.pair_service.wire_phase = CP_SERVING; }
        Ok(result)
    }
    pub fn try_receive_completed_pair(&mut self) -> Result<Option<CoordinatorCompletedPairEventV1>> {
        let result = self.receive_pair_inner(); if result.is_err() { self.core.close(); } result
    }
    fn receive_pair_inner(&mut self) -> Result<Option<CoordinatorCompletedPairEventV1>> {
        self.transport_check()?;
        if self.pair_service.closed { return Ok(None); }
        if let Some(c) = self.pair_service.cleanup { crate::channel::require_time(c)?; }
        let Some(packet) = self.tree.as_ref().ok_or_else(|| rejected("completed pair tree consumed"))?.completed_pair()?.completed_pair_receive()? else { return Ok(None); };
        let slot = &mut self.pair_service;
        let event = match packet {
            CP::Display { setup_challenge, witness_instance, serve_challenge, service_ceiling_ms, data } => {
                data.validate()?;
                let setup = slot.setup.as_ref().ok_or_else(|| rejected("unsolicited completed pair Display"))?;
                let x = &setup.wire.inputs.owners[0].selectors;
                if slot.wire_phase != CP_ADMITTED || slot.review.is_some() || setup_challenge != setup.wire.setup_challenge
                    || data.original != setup.wire.original || service_ceiling_ms == 0
                    || data.original.owners.iter().any(|o| service_ceiling_ms > o.source_ceiling_ms)
                    || data.endpoint != x.endpoint || data.server_name != x.server_name || data.witness_id != x.witness_id
                    || data.pinned_server_certificate_digest != x.pinned_server_certificate_digest
                    || !state::hash(&witness_instance) || !state::hash(&serve_challenge) {
                    return Err(rejected("completed pair Display binding"));
                }
                let now = Instant::now(); let wall = state::wall_ms()?;
                let service_deadline = self.clocks.restrict_received(PROFILE,service_ceiling_ms,setup.source_deadline,now)?
                    .min(crate::completed_pair_origin::completed_pair_service_wall_ceiling(now,wall,&data)?);
                let review_deadline = setup.ceiling.min(service_deadline).min(wall_ceiling(now,wall,data.prepared_at_ms,data.expires_at_ms)?);
                let b = Arc::new(Review { setup:Arc::clone(setup), data, instance:witness_instance, challenge:serve_challenge, service_ceiling_ms, service_deadline, review_deadline, last_wall:AtomicU64::new(wall) });
                b.review_current()?; slot.review = Some(Arc::clone(&b)); slot.wire_phase = CP_REVIEW;
                if !received_pair_progress(&self.core.phase,CP_ADMITTED,CP_REVIEW)? { CoordinatorCompletedPairEventV1::Restricted }
                else { CoordinatorCompletedPairEventV1::Display(FinancialCompletedPairReviewTicketV1{binding:b,consumed:false}) }
            }
            CP::Serving { setup_challenge,witness_instance,serve_challenge,presentation_digest } => {
                let b = slot.review.as_ref().ok_or_else(|| rejected("completed pair Serving before review"))?;
                if slot.wire_phase != CP_SERVING || slot.serving_ack || setup_challenge != b.setup.wire.setup_challenge
                    || witness_instance != b.instance || serve_challenge != b.challenge || presentation_digest != b.data.presentation_digest {
                    return Err(rejected("completed pair Serving binding"));
                }
                slot.serving_ack = true; b.bounds()?;
                if self.core.phase.pair_send_restricted(CP_SERVING)? { CoordinatorCompletedPairEventV1::Restricted }
                else {
                    let binding=Arc::clone(b);
                    let notice=Packet::CompletedPairServing { data:b.data.clone(), witness_instance:b.instance.clone(), serve_challenge:b.challenge.clone(), service_ceiling_ms:b.service_ceiling_ms };
                    let deadline=b.service_deadline;
                    if self.send_positive(&notice,deadline)? == FinancialSendProgressV1::Restricted { return Ok(Some(CoordinatorCompletedPairEventV1::Restricted)); }
                    self.pair_service.host_notified=true;
                    CoordinatorCompletedPairEventV1::Serving(FinancialCompletedPairServingV1{binding})
                }
            }
            CP::PreparationFailed{setup_challenge} => {
                if slot.failed || slot.review.is_some() || slot.setup.as_ref().is_none_or(|s|s.wire.setup_challenge!=setup_challenge) { return Err(rejected("completed pair preparation failure binding")); }
                slot.failed=true;self.core.phase.revoke();CoordinatorCompletedPairEventV1::PreparationFailed
            }
            CP::ServiceFailed{setup_challenge,witness_instance,presentation_digest} => {
                let b=slot.review.as_ref().ok_or_else(||rejected("completed pair failure before Display"))?;
                if slot.failed||slot.disposed||setup_challenge!=b.setup.wire.setup_challenge||witness_instance!=b.instance||presentation_digest!=b.data.presentation_digest{return Err(rejected("completed pair service failure binding"));}
                slot.failed=true;self.core.phase.revoke();CoordinatorCompletedPairEventV1::ServiceFailed
            }
            CP::Disposed{coordinator,session,cleanup_ceiling_ms} => {
                if coordinator!=self.coordinator||session!=self.session||slot.disposed||(!slot.finish_sent&&!slot.cancel_sent&&!slot.failed){return Err(rejected("completed pair disposal binding"));}
                let original=self.clocks.received_cleanup(cleanup_ceiling_ms,Instant::now())?;
                slot.cleanup=Some(self.clocks.retain_cleanup(slot.cleanup,original,Instant::now())?);slot.disposed=true;
                CoordinatorCompletedPairEventV1::Disposed
            }
            CP::PurposeClosed{coordinator,session} => {
                if coordinator!=self.coordinator||session!=self.session||!slot.disposed||!slot.close_sent||slot.closed{return Err(rejected("completed pair close binding"));}
                slot.closed=true;CoordinatorCompletedPairEventV1::PurposeClosed
            }
            _=>return Err(rejected("unexpected completed pair observation")),
        };Ok(Some(event))
    }
    /// Normal-close restriction only, from an actual acknowledged original
    /// Pair service already reported to H; never from caller presentation data.
    pub(super) fn normal_pair_lease(&self)->Result<CompletedPairServiceLease> {
        let slot=&self.pair_service;
        if !slot.serving_ack || !slot.host_notified || slot.finish_sent || slot.failed
            || slot.cancel_sent || slot.disposed || slot.closed || slot.wire_phase!=CP_SERVING {
            return Err(rejected("normal Finish requires actual current Pair service"));
        }
        let binding=Arc::clone(slot.review.as_ref().ok_or_else(||rejected("normal Finish Pair review missing"))?);
        let lease=CompletedPairServiceLease{binding};lease.check()?;Ok(lease)
    }
    /// Exclusive admitted normal-close owner only. This can stop the actual
    /// existing resource service, never admit another financial operation.
    pub(super) fn finish_completed_pair_for_normal(&mut self)->Result<()> {
        self.core.check()?;
        if self.core.phase.normal_phase()!=3 || self.core.phase.revoked() || self.core.phase.quiescent() {
            return Err(rejected("Pair normal finish outside admitted close"));
        }
        crate::channel::require_time(self.cleanup.ok_or_else(||rejected("Pair normal cleanup missing"))?)?;
        let slot=&mut self.pair_service;
        if !slot.serving_ack||!slot.host_notified||slot.finish_sent||slot.failed||slot.cancel_sent||slot.disposed||slot.closed||slot.wire_phase!=CP_SERVING {
            return Err(rejected("Pair normal finish without actual service"));
        }
        let b=slot.review.as_ref().ok_or_else(||rejected("Pair normal finish review missing"))?;
        self.core.phase.pair_step(CP_SERVING,CP_DONE)?;
        slot.finish_sent=true;slot.wire_phase=CP_DONE;
        let packet=CP::FinishService{setup_challenge:b.setup.wire.setup_challenge.clone(),witness_instance:b.instance.clone(),presentation_digest:b.data.presentation_digest.clone()};
        self.send_pair(&packet)
    }
    pub fn finish_completed_pair_service(&mut self)->Result<()> {
        self.core.check_action_restrictions()?;
        let slot=&mut self.pair_service;
        if !slot.serving_ack||!slot.host_notified||slot.finish_sent||slot.failed||slot.cancel_sent||slot.disposed{return Err(rejected("completed pair Finish without actual service"));}
        let b=slot.review.as_ref().ok_or_else(||rejected("completed pair Finish before review"))?;
        b.current()?;self.core.phase.pair_step(CP_SERVING,CP_DONE)?;slot.finish_sent=true;slot.wire_phase=CP_DONE;
        let packet=CP::FinishService{setup_challenge:b.setup.wire.setup_challenge.clone(),witness_instance:b.instance.clone(),presentation_digest:b.data.presentation_digest.clone()};
        self.send_pair(&packet)
    }
    pub fn close_completed_pair_purpose(&mut self)->Result<()> {
        let slot=&mut self.pair_service;
        if !slot.disposed||slot.close_sent{return Err(rejected("completed pair close before disposal"));}
        let original=slot.cleanup.ok_or_else(||rejected("completed pair cleanup missing"))?;
        slot.cleanup=Some(self.clocks.retain_cleanup(slot.cleanup,original,Instant::now())?);slot.close_sent=true;
        self.send_pair(&CP::ClosePurpose{coordinator:self.coordinator.clone(),session:self.session.clone()})
    }
    pub(super) fn cancel_completed_pair(&mut self)->Result<()> {
        if self.pair_service.closed||self.pair_service.cancel_sent{return Ok(());}
        self.pair_service.cancel_sent=true;
        self.send_pair(&CP::Cancel{coordinator:self.coordinator.clone(),session:self.session.clone()})
    }
}
impl CPState {
    pub(super) fn closed(&self)->bool{self.closed}
    pub(super) fn observe_active(&self,core:&Core)->Result<()> {
        match core.phase.pair_phase(){
            CP_SETUP|CP_ADMITTED=>self.setup.as_ref().ok_or_else(||rejected("completed pair active Setup missing"))?.check(),
            CP_REVIEW=>self.review.as_ref().ok_or_else(||rejected("completed pair active review missing"))?.review_current(),
            CP_SERVING=>self.review.as_ref().ok_or_else(||rejected("completed pair active service missing"))?.current(),
            _=>Ok(()),
        }
    }
}
fn received_pair_progress(phase:&Phases,from:u8,to:u8)->Result<bool>{
    if phase.pair_send_restricted(from)?{return Ok(false);}
    match phase.pair_step(from,to){Ok(())=>Ok(!phase.pair_send_restricted(to)?),Err(error)=>{if phase.pair_send_restricted(from)?{Ok(false)}else{Err(error)}}}
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn pair_both_native_admissions_deny_r_and_q(){
        for (before,after) in [(CP_SETUP,CP_ADMITTED),(CP_REVIEW,CP_SERVING)] {
            let q=Phases::new();q.pair_step(0,before).unwrap();q.begin_quiescence(q.snapshot()).unwrap();
            assert!(q.pair_step(before,after).is_err());assert!(q.pair_send_restricted(before).is_err());assert!(q.positive_send_restricted().is_err());
            let r=Phases::new();r.pair_step(0,before).unwrap();r.revoke();
            assert!(r.pair_step(before,after).is_err());assert!(r.pair_send_restricted(before).unwrap());assert!(r.positive_send_restricted().unwrap());
        }
    }
    #[test]fn pair_native_state_is_independent_and_preserves_restriction(){let p=Phases::new();p.pair_step(0,CP_ADMITTED).unwrap();assert_eq!(p.signing_phase(0),0);assert_eq!(p.signing_phase(1),0);p.revoke();assert!(!received_pair_progress(&p,CP_ADMITTED,CP_REVIEW).unwrap());assert_eq!(p.pair_phase(),CP_ADMITTED);assert!(received_pair_progress(&p,CP_REVIEW,CP_SERVING).is_err());}
    #[test]fn pair_does_not_bypass_exclusive_retirement(){let p=Phases::new();p.pair_step(0,CP_ADMITTED).unwrap();p.begin_quiescence(p.snapshot()).unwrap();assert!(received_pair_progress(&p,CP_ADMITTED,CP_REVIEW).is_err());}
}
