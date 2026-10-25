//! Exclusive C-owned terminal protocol. No liveness failure, outcome or DTO
//! can construct the private normal-reap proof used by Core tombstones.
use super::*;
use crate::host_interstage::{RetirementRequest,RetirementPurpose};
use crate::financial_witness_channel::{FinancialWitnessOutcomeV1,Packet as WP};
use std::time::Duration;
// Shared retirement code observes only an actual InitialHistory failure here.
// Neither a successful call nor another purpose gains a History-stage record.
macro_rules! history_retirement_detail {
    ($purpose:expr, $stage:ident, $operation:expr) => {{
        let result = $operation;
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        if let Err(error) = &result {
            if $purpose == RetirementPurpose::InitialHistory {
                use crate::financial_ci_actor_diagnostics as diagnostic;
                diagnostic::work_fallback(diagnostic::DriverStage::$stage,error);
            }
        }
        result
    }};
}
pub struct CoordinatorWitnessRetirementTicketV1{
    core:Arc<Core>,entries:Vec<Arc<EntryReviewed>>,request:RetirementRequest,cutoff:Instant,phases:u64,consumed:bool,
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
        self.core.phase.begin_quiescence(ticket.phases)?;ticket.consumed=true;
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
    /// Disposed and the received, unadmitted Writer Read create this ticket.
    /// While its automatic display is still in flight, retain ordinary receive
    /// and the original W cleanup cutoff; do not enter exclusive grammar yet.
    pub fn try_prepare_witness_retirement(&mut self,role:Target)->Result<Option<CoordinatorWitnessRetirementTicketV1>>{
        self.core.check_action_restrictions()?;let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::FinancialContinuation,role)?;
        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("retirement Signer missing"))?;
        if slot.wire_phase!=admit::AWAITING_NEXT_READ&&!slot.writer_acquire.signing_setup_pending(slot.wire_phase){return Err(rejected("retirement before exact S response"));}
        let(p,committed)=slot.admission.retained_result()?;
        let(instance,cutoff,outcome)=self.witnesses[role.index()].retirement_record()?;
        match outcome{
            FinancialWitnessOutcomeV1::Committed{presentation_digest:_,effect_commitment:_,head_sequence,head_digest}
                if *head_sequence==committed.head_sequence&&head_digest==&committed.head_digest=>{},
            _=>return Err(rejected("retirement S/W committed heads differ")),
        }
        self.witnesses[role.index()].retirement_matches_admit(p)?;
        // Exclusive H traffic is shared by both original owners. A different
        // owner can also have an automatic, not-yet-received display in flight.
        if self.slots.iter().flatten().any(|s|matches!(s.wire_phase,SOURCE_RETAINED|AWAITING_ADMISSION|admit::AWAITING_NEXT_READ)) {
            crate::channel::require_time(cutoff)?;
            return Ok(None);
        }
        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,purpose:RetirementPurpose::FinancialContinuation,binding_digest:p.presentation_digest.clone(),
            witness_instance:instance.to_owned(),challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:None};
        let cutoff=request.validate(self.clocks)?.min(cutoff);crate::channel::require_time(cutoff)?;
        Ok(Some(CoordinatorWitnessRetirementTicketV1{core:Arc::clone(&self.core),entries:self.slots.iter().flatten().filter_map(|s|s.entry.as_ref().map(Arc::clone)).collect(),request,cutoff,
            phases,consumed:false}))
    }
    pub fn prepare_signing_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{
        self.core.check_action_restrictions()?;
        let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::FinancialSigning,role)?;
        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("Signing retirement Source absent"))?;
        if slot.wire_phase!=67||!slot.activate.wallet.sign.selector_seen{return Err(rejected("Signing retirement before actual committed Sign and selector"));}
        let (activation,_)=slot.activate.wallet_predecessor()?;
        let (_,signed)=slot.activate.wallet.sign.return_predecessor()?;
        let (_,service,deadline)=self.signing_services[role.index()].retirement_source()?;
        activation.read.service.require_same(&service)?;
        let signing=crate::host_interstage::SigningRetirementBindingV1{original_commitment:service.original.commitment()?,signed:signed.clone()};
        let cutoff=deadline.min(activation.read.writer_deadline).min(self.clocks.supervision());
        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,purpose:RetirementPurpose::FinancialSigning,binding_digest:signing.commitment()?,witness_instance:service.witness_instance,challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:Some(signing)};
        request.validate(self.clocks)?;
        Ok(CoordinatorWitnessRetirementTicketV1{core:Arc::clone(&self.core),entries:self.slots.iter().flatten().filter_map(|s|s.entry.as_ref().map(Arc::clone)).collect(),request,cutoff,phases,consumed:false})
    }
    pub fn prepare_history_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{
        self.core.check_action_restrictions()?;let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::InitialHistory,role)?;
        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("History retirement Signer missing"))?;
        if slot.wire_phase!=HISTORY_RETAINED||slot.continue_deadline.is_none(){return Err(rejected("History retirement before authenticated retention"));}
        let read=slot.read.as_ref().ok_or_else(||rejected("History retirement Read missing"))?;
        let(instance,cutoff)=self.histories[role.index()].retirement_record(read)?;
        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,
            purpose:RetirementPurpose::InitialHistory,binding_digest:read.wire.presentation_digest.clone(),witness_instance:instance.to_owned(),challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:None};
        let cutoff=request.validate(self.clocks)?.min(cutoff);crate::channel::require_time(cutoff)?;
        Ok(CoordinatorWitnessRetirementTicketV1{core:Arc::clone(&self.core),entries:self.slots.iter().flatten().filter_map(|s|s.entry.as_ref().map(Arc::clone)).collect(),request,cutoff,phases,consumed:false})
    }
    fn retirement_idle(&self,phases:u64,purpose:RetirementPurpose,target:Target)->Result<()>{
        if !idle_phase_snapshot(phases,purpose,target.index()){return Err(rejected("active purpose in original retirement snapshot"));}
        if self.retirement_resume.is_some()||self.cancel_sent||pending(&self.core)||witness::witness_pending(&self.core){return Err(rejected("retirement has admitted outbound"));}
        for i in 0..2{
            if self.core.phase.phase(i)==writer_acquire::WRITER_READ_REVIEW && self.slots[i].as_ref().is_none_or(|s|!s.writer_acquire.signing_setup_pending(s.wire_phase)){return Err(rejected("retirement pending Writer Read provenance missing"));}
            let target_history=purpose==RetirementPurpose::InitialHistory&&target.index()==i;
            if !self.histories[i].retirement_idle(target_history){return Err(rejected("History service custody not quiescent"));}
            let target_signing=purpose==RetirementPurpose::FinancialSigning&&target.index()==i;
            if !(if target_signing{self.signing_services[i].normal_retirement_idle()}else{self.signing_services[i].retirement_idle()}){return Err(rejected("Signing service custody not quiescent"));}
            if let Some(entry)=self.slots[i].as_ref().and_then(|s|s.entry.as_ref()){entry.check_custody()?;}
            if !self.witnesses[i].retirement_idle(){return Err(rejected("active W purpose prevents retirement"));}
        }Ok(())
    }
    fn retirement_bounds(&self,cutoff:Instant)->Result<()>{
        crate::channel::require_time(cutoff)?;
        if !self.core.phase.quiescent()||self.core.phase.revoked(){return Err(rejected("retirement interrupted"));}
        for slot in self.slots.iter().flatten(){if let Some(entry)=&slot.entry{entry.retirement_clock_bounds()?;}}
        for service in &self.signing_services{if let Some(record)=service.retired_record(){record.check()?;}}Ok(())
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
    /// Scheduling observation only after this endpoint's actual owned reap and
    /// authenticated H Resume. A queue message alone cannot satisfy this record.
    pub fn finish_retirement_resume(&mut self)->Result<bool>{
        let cutoff=self.retirement_resume.ok_or_else(||rejected("no owned retirement awaiting native resume"))?;
        crate::channel::require_time(cutoff)?;self.core.check()?;
        for slot in self.slots.iter().flatten(){if let Some(entry)=&slot.entry{entry.check_custody()?;}}
        if self.core.phase.revoked(){return Err(rejected("retirement resume restricted"));}
        if self.core.phase.quiescent(){return Ok(false);}
        self.retirement_resume=None;Ok(true)
    }
    /// Sole driver only. All packet operations are nonblocking and each loop
    /// samples original actors/R/source/cleanup. Final fallback kernel reap on
    /// failure may block: no wall-bounded reap guarantee is claimed.
    pub fn retire_witness(&mut self,mut outbound:CoordinatorWitnessRetirementOutboundV1)->Result<CoordinatorWitnessRetiredV1>{
        let result=(||{
            let t=&outbound.ticket;
            let mut cutoff=t.cutoff;
            let signed_record=if t.request.purpose==RetirementPurpose::FinancialSigning {
                let slot=self.slots[t.request.target.index()].as_ref().ok_or_else(||rejected("Signing source absent"))?;
                let(a,_)=slot.activate.wallet_predecessor()?;
                let(_,signed)=slot.activate.wallet.sign.return_predecessor()?;
                let(entry,correlation,service)=self.signing_services[t.request.target.index()].retirement_source()?;
                Some((entry,correlation,signed.clone(),service,a.read.writer_deadline,self.signing_services[t.request.target.index()].retirement_wall_bounds()?))
            }else{None};
            if !Arc::ptr_eq(&self.core,&t.core){return history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,Err(rejected("foreign retirement outbound")));}
            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_bounds(cutoff))?;history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.core.check())?;history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_idle(t.phases,t.request.purpose,t.request.target))?;
            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_send_host(&Packet::RetireRequest{request:t.request.clone()},cutoff))?;
            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_wait_host(&t.request,false,cutoff,None))?;
            let i=t.request.target.index();
            match t.request.purpose{
                RetirementPurpose::FinancialSigning=>{
                    self.finish_signing_for_retirement(t.request.target)?;
                    loop {self.retirement_bounds(cutoff)?;self.core.check()?;
                        if let Some(event)=self.try_receive_signing()? {
                            match event {CoordinatorFinancialSigningEventV1::Disposed(role) if role==t.request.target=>{cutoff=cutoff.min(self.signing_retirement_cleanup(role)?);break;},_=>return Err(rejected("normal Signing retirement expected exact Disposed"))}
                        }std::thread::sleep(Duration::from_millis(1));
                    }
                    self.close_signing_purpose(t.request.target)?;
                    loop {self.retirement_bounds(cutoff)?;self.core.check()?;
                        if let Some(event)=self.try_receive_signing()? {match event {CoordinatorFinancialSigningEventV1::PurposeClosed(role) if role==t.request.target=>break,_=>return Err(rejected("normal Signing retirement expected exact PurposeClosed"))}}
                        std::thread::sleep(Duration::from_millis(1));
                    }
                },
                RetirementPurpose::FinancialContinuation=>{
                    self.close_witness_purpose(t.request.target)?;
                    loop{self.retirement_bounds(cutoff)?;self.core.check()?;
                        if let Some(packet)=self.tree.as_ref().unwrap().financial_witness(t.request.target)?.financial_witness_receive()?{
                            match packet{WP::PurposeClosed{coordinator,session} if coordinator==self.coordinator&&session==self.session=>{self.witnesses[i].retirement_closed()?;break;},
                                _=>return Err(rejected("append retirement expected exact PurposeClosed"))}}
                        std::thread::sleep(Duration::from_millis(1));
                    }
                },
                RetirementPurpose::InitialHistory=>{
                    history_retirement_detail!(t.request.purpose,HistoryRetirementPurposeClose,self.close_history_purpose(t.request.target))?;
                    loop{history_retirement_detail!(t.request.purpose,HistoryRetirementPurposeClose,self.retirement_bounds(cutoff))?;history_retirement_detail!(t.request.purpose,HistoryRetirementPurposeClose,self.core.check())?;
                        if let Some(packet)=history_retirement_detail!(t.request.purpose,HistoryRetirementPurposeClose,(||self.tree.as_ref().unwrap().financial_history(t.request.target)?.financial_history_receive())())?{
                            match packet{crate::financial_history_channel::Packet::PurposeClosed{coordinator,session} if coordinator==self.coordinator&&session==self.session=>{history_retirement_detail!(t.request.purpose,HistoryRetirementPurposeClose,self.histories[i].retirement_closed())?;break;},
                                _=>return history_retirement_detail!(t.request.purpose,HistoryRetirementPurposeClose,Err(rejected("History retirement expected exact PurposeClosed")))}}
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            let mut owner=history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.tree.as_mut().unwrap().take_witness_retirement(t.request.target,t.request.purpose,t.request.witness_instance.clone(),Arc::clone(&self.core)))?;
            let index=owner.index();
            let proof=loop{
                history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.retirement_bounds(cutoff))?;history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.core.check_retirement_other_roots(index))?;
                if let Some(proof)=history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,owner.advance(cutoff))?{break proof;}
                std::thread::sleep(Duration::from_millis(1));
            };
            if proof.instance()!=t.request.witness_instance{return history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,Err(rejected("retirement instance proof mismatch")));}
            history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.tree.as_mut().unwrap().install_retirement(&proof))?;history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.core.install_retired(&proof))?;
            match t.request.purpose{
                RetirementPurpose::FinancialSigning=>self.core.phase.signing_retirement_step(i,5,6)?,
                RetirementPurpose::FinancialContinuation=>self.witnesses[i].retirement_reaped()?,
                RetirementPurpose::InitialHistory=>{history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.histories[i].retirement_reaped())?;history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.core.phase.observe_history_retired(i))?;}
            }
            #[cfg(wholepact_financial_ci)]
            if t.request.purpose==RetirementPurpose::FinancialSigning{crate::financial_observer::signer(t.request.target,"SigningRetired")?;}
            history_retirement_detail!(t.request.purpose,HistoryRetirementHostResume,self.retirement_send_host(&Packet::RetireResume{request:t.request.clone()},cutoff))?;
            history_retirement_detail!(t.request.purpose,HistoryRetirementHostResume,self.retirement_wait_host(&t.request,true,cutoff,Some(index)))?;
            if let Some((entry,correlation,signed,service,writer,(service_valid_from_ms,service_valid_until_ms,last_wall)))=signed_record {
                let record=Arc::new(super::signed_custody::SignedResultRecord{core:Arc::clone(&self.core),entry,correlation,signed,service,writer,retired_index:index,service_valid_from_ms,service_valid_until_ms,last_wall:std::sync::atomic::AtomicU64::new(last_wall)});
                self.signing_services[i].install_retired_result(record)?;
            }
            self.retirement_resume=Some(cutoff);outbound.consumed=true;
            Ok(CoordinatorWitnessRetiredV1{core:Arc::clone(&self.core),entries:t.entries.iter().map(Arc::clone).collect(),role:t.request.target,cutoff:cutoff,consumed:false})
        })();
        if result.is_err(){self.core.close();}result
    }
}

// One immutable snapshot is validated and later supplied to the exact CAS.
// A phase alone never proves disposal: actual retained W records are separate.
// History5 is accepted only for the exact target with actual joined Disposed;
// History6 additionally requires its actual private normal-reap record. Signing
// permits only this actual signed target or a previously retired signed slot.
fn idle_phase_snapshot(word:u64,purpose:RetirementPurpose,target:usize)->bool{
    if word&((1u64<<30)|(1u64<<31))!=0||((word>>40)&15)!=0{return false;}
    (0..2).all(|i|{
        let signer=((word>>(i*8))&255)as u8;
        let signing=((word>>(32+i*4))&15)as u8;
        let signed=signer==67&&(signing==6||(purpose==RetirementPurpose::FinancialSigning&&i==target&&signing==4));
        (signed||matches!(signer,0|V3_HELD|SOURCE_RETAINED|HISTORY_RETAINED|AWAITING_ADMISSION|admit::AWAITING_NEXT_READ|writer_acquire::WRITER_READ_REVIEW))
        &&matches!(((word>>(16+i*4))&15)as u8,0|witness::W_ADMITTED)
        &&(match ((word>>(24+i*3))&7)as u8{0|history::H_RETIRED=>true,history::H_DONE=>purpose==RetirementPurpose::InitialHistory&&i==target,_=>false})
        &&(signing==0||(signing==6&&signer==67)||(purpose==RetirementPurpose::FinancialSigning&&i==target&&signing==4&&signer==67))
    })
}

#[cfg(test)]mod tests{use super::*;
#[test]fn retirement_idle_snapshot_precedes_native_race_and_never_infers_service_disposal(){
    let phase=Phases::new();phase.step(0,0,admit::AWAITING_NEXT_READ).unwrap();
    let before=phase.snapshot();assert!(idle_phase_snapshot(before,RetirementPurpose::FinancialContinuation,0));
    phase.step(1,0,ENTRY_PREPARING).unwrap();assert!(phase.begin_quiescence(before).is_err());
    assert!(!idle_phase_snapshot(phase.snapshot(),RetirementPurpose::FinancialContinuation,0));
    assert!(!idle_phase_snapshot(before|(5u64<<24),RetirementPurpose::FinancialContinuation,0));
    assert!(idle_phase_snapshot(before|(5u64<<24),RetirementPurpose::InitialHistory,0));
    assert!(!idle_phase_snapshot(before|(5u64<<24),RetirementPurpose::InitialHistory,1));
    assert!(!idle_phase_snapshot(before|(6u64<<32),RetirementPurpose::FinancialContinuation,0));
}
}

#[cfg(test)]mod writer_read_retirement_tests {use super::*;
 #[test]fn only_unadmitted_writer_review_can_pause_for_predecessor_retirement(){
  let p=Phases::new();p.step(0,0,writer_acquire::WRITER_READ_REVIEW).unwrap();assert!(idle_phase_snapshot(p.snapshot(),RetirementPurpose::FinancialContinuation,0));
  p.step(0,writer_acquire::WRITER_READ_REVIEW,writer_acquire::WRITER_READ_ADMITTED).unwrap();assert!(!idle_phase_snapshot(p.snapshot(),RetirementPurpose::FinancialContinuation,0));
 }
}

#[cfg(test)]mod sequential_signing_retirement_tests {
 use super::*;
 #[test]fn first_signing_retires_without_second_signer_started(){let p=Phases::new();p.step(0,0,67).unwrap();p.signing_step(0,0,4).unwrap();assert!(idle_phase_snapshot(p.snapshot(),RetirementPurpose::FinancialSigning,0));assert!(!idle_phase_snapshot(p.snapshot(),RetirementPurpose::FinancialSigning,1));}
 #[test]fn second_history_can_retire_after_first_signed_reap(){let p=Phases::new();p.step(0,0,67).unwrap();p.signing_step(0,0,6).unwrap();p.step(1,0,HISTORY_RETAINED).unwrap();p.history_step(1,0,5).unwrap();assert!(idle_phase_snapshot(p.snapshot(),RetirementPurpose::InitialHistory,1));}
 #[test]fn another_active_signing_or_action_prevents_retirement(){let p=Phases::new();p.step(0,0,67).unwrap();p.signing_step(0,0,4).unwrap();p.step(1,0,67).unwrap();p.signing_step(1,0,4).unwrap();assert!(!idle_phase_snapshot(p.snapshot(),RetirementPurpose::FinancialSigning,0));}
 #[test]fn retired_phase_without_signed_source_is_not_idle_proof(){let p=Phases::new();p.signing_step(0,0,6).unwrap();assert!(!idle_phase_snapshot(p.snapshot(),RetirementPurpose::InitialHistory,1));}
}

#[cfg(test)]
mod retirement_error_observation_tests {
    use super::*;
    #[test]
    fn history_retirement_observation_preserves_operation_and_original_io_error() {
        for purpose in [RetirementPurpose::InitialHistory,RetirementPurpose::FinancialContinuation,RetirementPurpose::FinancialSigning] {
            let calls=std::cell::Cell::new(0);
            let purpose_reads=std::cell::Cell::new(0);
            let ok:Result<u8>=history_retirement_detail!({purpose_reads.set(purpose_reads.get()+1);purpose},HistoryRetirementHostQuiescence,{
                calls.set(calls.get()+1);Ok(7)
            });
            assert_eq!(ok.unwrap(),7);assert_eq!(calls.get(),1);assert_eq!(purpose_reads.get(),0);
            let failed:Result<()>=history_retirement_detail!({purpose_reads.set(purpose_reads.get()+1);purpose},HistoryRetirementOwnedStopReap,{
                calls.set(calls.get()+1);Err(std::io::Error::from_raw_os_error(libc::EACCES))
            });
            let error=failed.unwrap_err();
            assert_eq!(calls.get(),2);assert_eq!(error.kind(),std::io::ErrorKind::PermissionDenied);
            assert_eq!(error.raw_os_error(),Some(libc::EACCES));
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            assert_eq!(purpose_reads.get(),1);
            #[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
            assert_eq!(purpose_reads.get(),0);
        }
    }
}
