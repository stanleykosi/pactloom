//! Denial-only custody installed after this C's actual owned Signing reap and
//! exact H Resume. No parser, public constructor, cloning grant or renewed clock.
use super::*;
use crate::{FinancialSigningOriginalV1,FinancialSigningServiceV1,SignerSignCommittedV1};
pub(super) struct SignedResultRecord {
    pub(super) core:Arc<Core>,pub(super) entry:Arc<EntryReviewed>,
    pub(super) correlation:FinancialSigningServiceV1,pub(super) signed:SignerSignCommittedV1,
    pub(super) service:Instant,pub(super) writer:Instant,pub(super) writer_wall:Instant,pub(super) retired_index:usize,
    pub(super) service_valid_from_ms:u64,pub(super) service_valid_until_ms:u64,pub(super) last_wall:std::sync::atomic::AtomicU64,
}
// Only fatal restriction observers publish this local classification.
// Ordinary current/retain/lease checks never latch a driver.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
#[derive(Clone,Copy)]
enum SignedResultCheckSite {OriginalDeadline,EntryBounds,SharedWallRead,SharedWallRejected,ServiceWallBefore,ServiceWallExpired,Restricted,SigningPhase,RetiredIndex,RetiredRoot,Core,FinalRestricted}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
#[derive(Clone,Copy)]
struct SignedResultCheckFailure {site:SignedResultCheckSite,minimum_bounds:u8}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
macro_rules! signed_result_check_at {
    ($capture:ident,$site:ident,$operation:expr) => {
        ($operation).inspect_err(|_| {
            if let Some(detail)=$capture.as_deref_mut(){*detail=Some(SignedResultCheckFailure{site:SignedResultCheckSite::$site,minimum_bounds:0});}
        })
    };
    ($capture:ident,$this:expr,$original:expr,$operation:expr) => {
        ($operation).inspect_err(|_| {
            if let Some(detail)=$capture.as_deref_mut(){
                let minimum_bounds=u8::from($this.service==$original)
                    |(u8::from($this.writer==$original)<<1)
                    |(u8::from($this.writer_wall==$original)<<2)
                    |(u8::from($this.entry.original_source==$original)<<3);
                *detail=Some(SignedResultCheckFailure{site:SignedResultCheckSite::OriginalDeadline,minimum_bounds});
            }
        })
    };
}
#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
macro_rules! signed_result_check_at {
    ($capture:ident,$site:ident,$operation:expr) => {$operation};
    ($capture:ident,$this:expr,$original:expr,$operation:expr) => {$operation};
}
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
macro_rules! signed_result_denied_at {
    ($capture:ident,$site:ident,$predicate:expr) => {{
        let denied=$predicate;
        if denied {if let Some(detail)=$capture.as_deref_mut(){*detail=Some(SignedResultCheckFailure{site:SignedResultCheckSite::$site,minimum_bounds:0});}}
        denied
    }};
}
#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
macro_rules! signed_result_denied_at {
    ($capture:ident,$site:ident,$predicate:expr) => {$predicate};
}
impl SignedResultRecord {
    pub(super) fn check(&self)->Result<()> {
        #[cfg(wholepact_financial_rendered_host_semantic_ci)]
        let result=self.check_impl(None);
        #[cfg(not(wholepact_financial_rendered_host_semantic_ci))]
        let result=self.check_impl();
        result
    }
    fn check_impl(&self,#[cfg(wholepact_financial_rendered_host_semantic_ci)] mut capture:Option<&mut Option<SignedResultCheckFailure>>)->Result<()> {
        let original=self.service.min(self.writer).min(self.writer_wall).min(self.entry.original_source);
        signed_result_check_at!(capture,self,original,crate::channel::require_time(original))?;
        signed_result_check_at!(capture,EntryBounds,self.entry.retirement_clock_bounds())?;
        let wall=signed_result_check_at!(capture,SharedWallRejected,signed_result_check_at!(capture,SharedWallRead,state::observe_shared_wall(&self.last_wall,original,state::wall_ms))?
            .ok_or_else(||rejected("retired Signing original wall bounds")))?;
        if signed_result_denied_at!(capture,ServiceWallBefore,wall<self.service_valid_from_ms)||signed_result_denied_at!(capture,ServiceWallExpired,wall>=self.service_valid_until_ms){return Err(rejected("retired Signing original wall bounds"));}
        if signed_result_denied_at!(capture,Restricted,self.core.phase.revoked()) || signed_result_denied_at!(capture,SigningPhase,self.core.phase.signing_phase(self.entry.slot())!=6)
            || signed_result_denied_at!(capture,RetiredIndex,self.retired_index>=32) || signed_result_denied_at!(capture,RetiredRoot,self.core.retired_roots.load(Ordering::Acquire)&(1<<self.retired_index)==0) {
            return Err(rejected("actual retired signed custody restricted"));
        }
        // A separate actual exclusive owner checks all non-target actors during
        // Q. This observer cannot authorize an effect or skip an actor itself.
        if !self.core.phase.quiescent(){signed_result_check_at!(capture,Core,self.core.check())?;}
        if signed_result_denied_at!(capture,FinalRestricted,self.core.phase.revoked()){return Err(rejected("retired signed custody revoked"));}
        Ok(())
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    pub(super) fn check_for_restriction(&self)->Result<()> {
        let mut detail=None;
        let result=self.check_impl(Some(&mut detail));
        if let (Err(error),Some(detail))=(&result,detail){
            use crate::financial_ci_actor_diagnostics as d;
            let pair=match detail.site {
                SignedResultCheckSite::OriginalDeadline=> (d::DriverStage::SignedResultOwner1OriginalDeadline,d::DriverStage::SignedResultOwner2OriginalDeadline),
                SignedResultCheckSite::EntryBounds=> (d::DriverStage::SignedResultOwner1EntryBounds,d::DriverStage::SignedResultOwner2EntryBounds),
                SignedResultCheckSite::SharedWallRead=> (d::DriverStage::SignedResultOwner1SharedWallRead,d::DriverStage::SignedResultOwner2SharedWallRead),
                SignedResultCheckSite::SharedWallRejected=> (d::DriverStage::SignedResultOwner1SharedWallRejected,d::DriverStage::SignedResultOwner2SharedWallRejected),
                SignedResultCheckSite::ServiceWallBefore=> (d::DriverStage::SignedResultOwner1ServiceWallBefore,d::DriverStage::SignedResultOwner2ServiceWallBefore),
                SignedResultCheckSite::ServiceWallExpired=> (d::DriverStage::SignedResultOwner1ServiceWallExpired,d::DriverStage::SignedResultOwner2ServiceWallExpired),
                SignedResultCheckSite::Restricted=> (d::DriverStage::SignedResultOwner1Restricted,d::DriverStage::SignedResultOwner2Restricted),
                SignedResultCheckSite::SigningPhase=> (d::DriverStage::SignedResultOwner1SigningPhase,d::DriverStage::SignedResultOwner2SigningPhase),
                SignedResultCheckSite::RetiredIndex=> (d::DriverStage::SignedResultOwner1RetiredIndex,d::DriverStage::SignedResultOwner2RetiredIndex),
                SignedResultCheckSite::RetiredRoot=> (d::DriverStage::SignedResultOwner1RetiredRoot,d::DriverStage::SignedResultOwner2RetiredRoot),
                SignedResultCheckSite::Core=> (d::DriverStage::SignedResultOwner1Core,d::DriverStage::SignedResultOwner2Core),
                SignedResultCheckSite::FinalRestricted=> (d::DriverStage::SignedResultOwner1FinalRestricted,d::DriverStage::SignedResultOwner2FinalRestricted),
            };
            let stage=match self.correlation.original.actor.signer_role {Target::Signer1=>pair.0,Target::Signer2=>pair.1};
            if matches!(detail.site,SignedResultCheckSite::OriginalDeadline){d::driver_minimum_detail(stage,d::classify_io(error.kind()),detail.minimum_bounds);}
            else{d::driver_detail(stage,d::classify_io(error.kind()));}
        }
        result
    }
}
pub struct FinancialSignedResultCustodyV1 {pub(super) record:Arc<SignedResultRecord>}
impl FinancialSignedResultCustodyV1 {
    pub fn role(&self)->Target{self.record.correlation.original.actor.signer_role}
    pub fn original_binding(&self)->&FinancialSigningOriginalV1{&self.record.correlation.original}
    pub fn signed_result(&self)->&SignerSignCommittedV1{&self.record.signed}
    pub fn original_service_deadline(&self)->Instant{self.record.service}
    pub fn original_writer_deadline(&self)->Instant{self.record.writer}
    pub fn check_current(&self)->Result<()>{self.record.check()}
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    pub(crate) fn check_current_for_fatal_observation(&self)->Result<()>{self.record.check_for_restriction()}
    pub(super) fn retain(&self)->Result<SignedResultLease>{self.check_current()?;Ok(SignedResultLease{record:Arc::clone(&self.record)})}
}
pub(super) struct SignedResultLease {record:Arc<SignedResultRecord>}
impl SignedResultLease {
    pub(super) fn check(&self)->Result<()>{self.record.check()}
    pub(super) fn original_binding(&self)->&FinancialSigningOriginalV1{&self.record.correlation.original}
    pub(super) fn signed_result(&self)->&SignerSignCommittedV1{&self.record.signed}
    pub(super) fn original_service_deadline(&self)->Instant{self.record.service}
    pub(super) fn original_writer_deadline(&self)->Instant{self.record.writer}
    pub(super) fn correlation(&self)->FinancialSigningServiceV1{self.record.correlation.clone()}
    pub(super) fn require_same(&self,core:&Arc<Core>,original:&FinancialSigningOriginalV1,signed:&SignerSignCommittedV1)->Result<()>{
        self.check()?;if !Arc::ptr_eq(core,&self.record.core)||original!=self.original_binding()||signed!=self.signed_result(){return Err(rejected("retired signed custody original changed"));}Ok(())
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn signed_result_custody(&self,role:Target)->Result<FinancialSignedResultCustodyV1>{
        self.core.check_action_restrictions()?;
        if self.retirement_resume.is_some(){return Err(rejected("Signing retirement native resume pending"));}
        let record=self.signing_services[role.index()].retired_record().ok_or_else(||rejected("actual Signing retirement absent"))?;
        let custody=FinancialSignedResultCustodyV1{record:Arc::clone(record)};custody.check_current()?;Ok(custody)
    }
}
