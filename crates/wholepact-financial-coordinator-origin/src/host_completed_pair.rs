//! Same-H immutable Pair restriction, not a financial action or direct W peer.
//! The receive gate requires two actual Signing retirement records. This slice
//! intentionally provides no producer for those records: positive handoff is
//! unavailable until the separately reviewed normal Signing retirement join.
use super::*;
use crate::completed_pair_data::{CompletedPairOriginalV1,CompletedPairPresentationV1};
use crate::financial_signing_data::FinancialSigningOriginalV1;
use std::sync::{OnceLock,atomic::AtomicU64};

// Not Clone, serde or public. Only the later exact H normal-retirement path may
// populate these slots. History/Continuation completion cannot stand in for it.
struct SigningRetiredRecord {
    role:SignerContinueRoleV1,witness_instance:String,original_commitment:String,signed_result_digest:String,
}
#[derive(Default)]
pub(crate) struct HostPairReceiveState {
    signing_retired:[Option<SigningRetiredRecord>;2],received:bool,
}
impl HostPairReceiveState {
    pub(crate) fn record_signing_retired(&mut self,request:&RetirementRequest)->Result<()> {
        if request.purpose!=RetirementPurpose::FinancialSigning{return Err(rejected("wrong Pair retirement purpose"));}
        let b=request.signing.as_ref().ok_or_else(||rejected("Pair retirement signed binding missing"))?;b.validate()?;
        let i=request.target.index();if self.received||self.signing_retired[i].is_some(){return Err(rejected("Pair retirement repeated"));}
        self.signing_retired[i]=Some(SigningRetiredRecord{role:request.target,witness_instance:request.witness_instance.clone(),original_commitment:b.original_commitment.clone(),signed_result_digest:b.commitment()?});Ok(())
    }
    fn require_retired(&self,original:&CompletedPairOriginalV1)->Result<()>{
        for (i,o) in original.owners.iter().enumerate(){
            let r=self.signing_retired[i].as_ref().ok_or_else(||rejected("Pair requires actual normal Signing retirement"))?;
            if r.role!=o.actor.signer_role||r.role.index()!=i||!hash(&r.witness_instance)||!hash(&r.signed_result_digest)
                ||r.original_commitment!=o.commitment()?{return Err(rejected("Pair Signing retirement provenance changed"));}
        }Ok(())
    }
    pub(crate) fn receive(&mut self,lifecycle:&Arc<HostLifecycle>,data:CompletedPairPresentationV1,
        witness_instance:String,serve_challenge:String,service_ceiling_ms:u64,expected:[FinancialSigningOriginalV1;2])->Result<()>{
        data.validate()?;
        if self.received||data.original.owners!=expected||!hash(&witness_instance)||!hash(&serve_challenge){return Err(rejected("Host Pair service correlation changed"));}
        self.require_retired(&data.original)?;
        lifecycle.check_wait()?;
        if lifecycle.state.load(Ordering::SeqCst)!=PARKED
            ||lifecycle.request.lock().map_err(|_|rejected("Host Pair retirement record poisoned"))?.is_some(){return Err(rejected("Host Pair receive outside settled park"));}
        let now=Instant::now();let wall=crate::signer_continue_state::wall_ms()?;
        let source0=lifecycle.clocks.restrict_received(PROFILE,data.original.owners[0].source_ceiling_ms,lifecycle.clocks.supervision(),now)?;
        let source1=lifecycle.clocks.restrict_received(PROFILE,data.original.owners[1].source_ceiling_ms,lifecycle.clocks.supervision(),now)?;
        if service_ceiling_ms>data.original.owners[0].source_ceiling_ms||service_ceiling_ms>data.original.owners[1].source_ceiling_ms{
            return Err(rejected("Host Pair service exceeds original source"));}
        let deadline=lifecycle.clocks.restrict_received(PROFILE,service_ceiling_ms,source0.min(source1),now)?
            .min(crate::financial_workflow_source::wall_ceiling(now,wall,data.valid_from_ms,data.valid_until_ms)?);
        let record=Arc::new(PairServiceRecord{data,witness_instance,serve_challenge,deadline,sources:[source0,source1],last_wall:AtomicU64::new(wall)});
        record.check(lifecycle)?;
        lifecycle.pair_service.set(record).map_err(|_|rejected("Host Pair service already retained"))?;
        self.received=true;Ok(())
    }
}
pub(super) struct PairServiceRecord {
    data:CompletedPairPresentationV1,witness_instance:String,serve_challenge:String,
    deadline:Instant,sources:[Instant;2],last_wall:AtomicU64,
}
impl PairServiceRecord {
    fn check(&self,lifecycle:&HostLifecycle)->Result<()>{
        lifecycle.check_not_poisoned()?;require_time(self.deadline)?;
        for source in self.sources{require_time(source)?;}
        let wall=crate::signer_continue_state::wall_ms()?;let old=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<old||wall<self.data.valid_from_ms||wall>=self.data.valid_until_ms
            ||self.data.original.owners.iter().any(|o|wall>=o.source_expires_at_ms){return Err(rejected("Host Pair original wall bound"));}
        // Nonrecursive, zero-wait original actor/channel/pidfd/session checks and
        // final shared-R load. No source read, receive, lock, or foreign W proof.
        lifecycle.checks.check_current()
    }
}
/// Created only after matching original C service receive and both actual
/// Signing retirement records. Send+Sync check-only observer; no Clone/import.
pub struct HostCompletedPairServiceV1 {lifecycle:Arc<HostLifecycle>,record:Arc<PairServiceRecord>}
impl HostCompletedPairServiceV1 {
    pub fn original_binding(&self)->&CompletedPairOriginalV1{&self.record.data.original}
    pub fn presentation(&self)->&CompletedPairPresentationV1{&self.record.data}
    pub fn original_service_deadline(&self)->Instant{self.record.deadline}
    pub fn check_current(&self)->Result<()>{self.record.check(&self.lifecycle)}
    pub(crate) fn matches_lifecycle(&self,lifecycle:&Arc<HostLifecycle>)->Result<()>{
        if !Arc::ptr_eq(lifecycle,&self.lifecycle)||lifecycle.pair_service.get().is_none_or(|r|!Arc::ptr_eq(r,&self.record)){
            return Err(rejected("Pair observer belongs to another original Host"));}
        self.check_current()
    }
}
impl HostFinancialInterstageWaitV1 {
    /// Remain parked while the foreground postchecks its actual retained owners
    /// and installs the returned restriction observer. This does not release H.
    pub fn wait_completed_pair_service(mut self)->Result<(Self,HostCompletedPairServiceV1)>{
        loop{
            self.state.check_wait()?;
            if let Some(guard)=self.try_next_retirement()?{guard.wait_resume()?;continue;}
            if let Some(record)=self.state.pair_service.get(){
                if self.state.state.load(Ordering::SeqCst)!=PARKED
                    ||self.state.request.lock().map_err(|_|rejected("Host Pair wait poisoned"))?.is_some(){return Err(rejected("Host Pair handoff not settled"));}
                self.state.pair_handoff.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire).map_err(|_|rejected("Host Pair handoff consumed"))?;
                let service=HostCompletedPairServiceV1{lifecycle:Arc::clone(&self.state),record:Arc::clone(record)};
                service.check_current()?;return Ok((self,service));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    /// Same sealed observer identity only. The pinned Host caller postchecks and
    /// installs its actual service while still parked before this native-free
    /// release. No boolean or ordinary presentation can unpark the owner.
    pub fn leave_after_completed_pair_service(mut self,service:&HostCompletedPairServiceV1)->Result<HostFinancialForegroundV1>{
        service.matches_lifecycle(&self.state)?;self.state.check_wait()?;
        if !self.state.pair_handoff.load(Ordering::Acquire)
            ||self.state.request.lock().map_err(|_|rejected("Host Pair leave poisoned"))?.is_some(){return Err(rejected("Host Pair handoff missing or retirement pending"));}
        self.state.state.compare_exchange(PARKED,RUNNING,Ordering::SeqCst,Ordering::SeqCst).map_err(|_|rejected("Host Pair release raced restriction"))?;
        service.check_current()?;self.consumed=true;
        Ok(HostFinancialForegroundV1{state:Arc::clone(&self.state),consumed:false,_thread:PhantomData})
    }
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn host_pair_observer_is_send_sync_without_constructing_any_custody(){fn require<T:Send+Sync>(){} require::<HostCompletedPairServiceV1>();}
    #[test]fn pair_receive_state_has_no_default_signing_retirement_proof(){let state=HostPairReceiveState::default();assert!(state.signing_retired.iter().all(Option::is_none));assert!(!state.received);}
}

impl HostLifecycle {
 pub(crate) fn normal_pair_presentation(&self)->Result<CompletedPairPresentationV1>{
  let record=self.pair_service.get().ok_or_else(||rejected("normal completion before actual Pair"))?;record.check(self)?;Ok(record.data.clone())
 }
}
