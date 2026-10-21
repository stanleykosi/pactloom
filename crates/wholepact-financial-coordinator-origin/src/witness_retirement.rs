//! Exclusive C-owned terminal protocol. No liveness failure, outcome or DTO
//! can construct the private normal-reap proof used by Core tombstones.
use super::*;
use crate::host_interstage::RetirementRequest;
use crate::financial_witness_channel::{FinancialWitnessOutcomeV1,Packet as WP};
use std::time::Duration;
pub struct CoordinatorWitnessRetirementTicketV1{
    core:Arc<Core>,entries:Vec<Arc<EntryReviewed>>,request:RetirementRequest,cutoff:Instant,signers:[u8;2],witnesses:[u8;2],consumed:bool,
}
impl CoordinatorWitnessRetirementTicketV1{
    pub fn role(&self)->Target{self.request.target}
    pub fn deadline(&self)->Instant{self.cutoff}
}
impl Drop for CoordinatorWitnessRetirementTicketV1{fn drop(&mut self){if !self.consumed{self.core.phase.revoke();}}}
pub struct CoordinatorWitnessRetirementOutboundV1{ticket:CoordinatorWitnessRetirementTicketV1,consumed:bool}
impl Drop for CoordinatorWitnessRetirementOutboundV1{fn drop(&mut self){if !self.consumed{self.ticket.core.phase.revoke();}}}
/// Returned only after exact normal reap/tombstone and matching H guard Resume.
/// It grants no source action. Native tail consumes it only to remove its pause.
pub struct CoordinatorWitnessRetiredV1{core:Arc<Core>,entries:Vec<Arc<EntryReviewed>>,role:Target,cutoff:Instant,consumed:bool}
impl CoordinatorWitnessRetiredV1{pub fn role(&self)->Target{self.role}}
impl Drop for CoordinatorWitnessRetiredV1{fn drop(&mut self){if !self.consumed{self.core.phase.revoke();}}}
impl CoordinatorFinancialNativeV1{
    /// The pinned native tail has already suspended positive/currentness and
    /// PTY work. Raw interruption handling continues and can always publish R.
    pub fn pause_for_witness_retirement(&self,mut ticket:CoordinatorWitnessRetirementTicketV1)->Result<CoordinatorWitnessRetirementOutboundV1>{
        if !Arc::ptr_eq(&self.core,&ticket.core){self.revoke();return Err(rejected("foreign retirement ticket"));}
        self.core.check_action_restrictions()?;crate::channel::require_time(ticket.cutoff)?;
        for entry in &ticket.entries{entry.check_custody()?;}
        if pending(&self.core)||witness::witness_pending(&self.core){return Err(rejected("admitted Final prevents retirement"));}
        self.core.phase.begin_quiescence(ticket.signers,ticket.witnesses)?;ticket.consumed=true;
        Ok(CoordinatorWitnessRetirementOutboundV1{ticket,consumed:false})
    }
    pub fn resume_after_witness_retirement(&self,mut retired:CoordinatorWitnessRetiredV1)->Result<()>{
        if !Arc::ptr_eq(&self.core,&retired.core){self.revoke();return Err(rejected("foreign retirement completion"));}
        self.core.check()?;crate::channel::require_time(retired.cutoff)?;
        for entry in &retired.entries{entry.check_custody()?;}
        self.core.phase.finish_quiescence()?;retired.consumed=true;Ok(())
    }
}
impl CoordinatorFinancialEndpointV1{
    /// Only authenticated matching S/W successful results plus actual W
    /// Disposed create this fixed-purpose ticket. Other W purposes have no
    /// conversion until their real source disposal adapter is joined.
    pub fn prepare_witness_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{
        self.core.check_action_restrictions()?;self.retirement_idle()?;
        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("retirement Signer missing"))?;
        if slot.wire_phase!=admit::AWAITING_NEXT_READ{return Err(rejected("retirement before exact S response"));}
        let(p,committed)=slot.admission.retained_result()?;
        let(instance,cutoff,outcome)=self.witnesses[role.index()].retirement_record()?;
        match outcome{
            FinancialWitnessOutcomeV1::Committed{presentation_digest:_,effect_commitment:_,head_sequence,head_digest}
                if *head_sequence==committed.head_sequence&&head_digest==&committed.head_digest=>{},
            _=>return Err(rejected("retirement S/W committed heads differ")),
        }
        self.witnesses[role.index()].retirement_matches_admit(p)?;
        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,
            witness_instance:instance.to_owned(),challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?};
        let cutoff=request.validate(self.clocks)?.min(cutoff);crate::channel::require_time(cutoff)?;
        Ok(CoordinatorWitnessRetirementTicketV1{core:Arc::clone(&self.core),entries:self.slots.iter().flatten().filter_map(|s|s.entry.as_ref().map(Arc::clone)).collect(),request,cutoff,
            signers:std::array::from_fn(|i|self.core.phase.phase(i)),witnesses:std::array::from_fn(|i|self.core.phase.witness_phase(i)),consumed:false})
    }
    fn retirement_idle(&self)->Result<()>{
        if self.cancel_sent||pending(&self.core)||witness::witness_pending(&self.core){return Err(rejected("retirement has admitted outbound"));}
        for i in 0..2{
            let phase=self.core.phase.phase(i);
            if !matches!(phase,V3_HELD|SOURCE_RETAINED|HISTORY_RETAINED|AWAITING_ADMISSION|admit::AWAITING_NEXT_READ){return Err(rejected("active Signer purpose prevents retirement"));}
            if let Some(entry)=self.slots[i].as_ref().and_then(|s|s.entry.as_ref()){entry.check_custody()?;}
            if !self.witnesses[i].retirement_idle(){return Err(rejected("active W purpose prevents retirement"));}
        }Ok(())
    }
    fn retirement_bounds(&self,cutoff:Instant)->Result<()>{
        crate::channel::require_time(cutoff)?;
        if !self.core.phase.quiescent()||self.core.phase.revoked(){return Err(rejected("retirement interrupted"));}
        for slot in self.slots.iter().flatten(){if let Some(entry)=&slot.entry{entry.retirement_clock_bounds()?;}}Ok(())
    }
    fn retirement_send_host(&self,p:&Packet,cutoff:Instant)->Result<()>{
        self.retirement_bounds(cutoff)?;
        self.tree.as_ref().ok_or_else(||rejected("retirement tree consumed"))?.continue_host()?.workflow_send(p)
    }
    fn retirement_wait_host(&self,request:&RetirementRequest,resumed:bool,cutoff:Instant,index:Option<usize>)->Result<()>{
        loop{
            self.retirement_bounds(cutoff)?;
            if let Some(index)=index{self.core.check_retirement_other_roots(index)?;}else{self.core.check()?;}
            if let Some(packet)=self.tree.as_ref().ok_or_else(||rejected("retirement tree consumed"))?.continue_host()?.workflow_receive()?{
                let received=match packet{Packet::RetireQuiescent{request} if !resumed=>request,Packet::RetireResumed{request} if resumed=>request,
                    _=>return Err(rejected("unexpected traffic during exclusive retirement"))};
                if &received!=request{return Err(rejected("retirement H observation mismatch"));}return Ok(());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    /// Sole driver only. All packet operations are nonblocking and each loop
    /// samples original actors/R/source/cleanup. Final fallback kernel reap on
    /// failure may block: no wall-bounded reap guarantee is claimed.
    pub fn retire_witness(&mut self,mut outbound:CoordinatorWitnessRetirementOutboundV1)->Result<CoordinatorWitnessRetiredV1>{
        let result=(||{
            let t=&outbound.ticket;
            if !Arc::ptr_eq(&self.core,&t.core){return Err(rejected("foreign retirement outbound"));}
            self.retirement_bounds(t.cutoff)?;self.core.check()?;self.retirement_idle()?;
            self.retirement_send_host(&Packet::RetireRequest{request:t.request.clone()},t.cutoff)?;
            self.retirement_wait_host(&t.request,false,t.cutoff,None)?;
            let i=t.request.target.index();
            self.close_witness_purpose(t.request.target)?;
            loop{
                self.retirement_bounds(t.cutoff)?;self.core.check()?;
                if let Some(packet)=self.tree.as_ref().unwrap().financial_witness(t.request.target)?.financial_witness_receive()?{
                    match packet{WP::PurposeClosed{coordinator,session} if coordinator==self.coordinator&&session==self.session=>{
                        self.witnesses[i].retirement_closed()?;break;
                    },_=>return Err(rejected("retirement expected exact PurposeClosed"))}
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut owner=self.tree.as_mut().unwrap().take_witness_retirement(t.request.target,t.request.witness_instance.clone(),Arc::clone(&self.core))?;
            let index=owner.index();
            let proof=loop{
                self.retirement_bounds(t.cutoff)?;self.core.check_retirement_other_roots(index)?;
                if let Some(proof)=owner.advance(t.cutoff)?{break proof;}
                std::thread::sleep(Duration::from_millis(1));
            };
            if proof.instance()!=t.request.witness_instance{return Err(rejected("retirement instance proof mismatch"));}
            self.tree.as_mut().unwrap().install_retirement(&proof)?;self.core.install_retired(&proof)?;
            self.witnesses[i].retirement_reaped()?;
            self.retirement_send_host(&Packet::RetireResume{request:t.request.clone()},t.cutoff)?;
            self.retirement_wait_host(&t.request,true,t.cutoff,Some(index))?;
            outbound.consumed=true;
            Ok(CoordinatorWitnessRetiredV1{core:Arc::clone(&self.core),entries:t.entries.iter().map(Arc::clone).collect(),role:t.request.target,cutoff:t.cutoff,consumed:false})
        })();
        if result.is_err(){self.core.close();}result
    }
}
