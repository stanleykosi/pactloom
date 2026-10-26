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
impl SignedResultRecord {
    pub(super) fn check(&self)->Result<()> {
        crate::channel::require_time(self.service.min(self.writer).min(self.writer_wall).min(self.entry.original_source))?;
        self.entry.retirement_clock_bounds()?;
        let wall=state::wall_ms()?;let prior=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<prior||wall<self.service_valid_from_ms||wall>=self.service_valid_until_ms{return Err(rejected("retired Signing original wall bounds"));}
        if self.core.phase.revoked() || self.core.phase.signing_phase(self.entry.slot())!=6
            || self.retired_index>=32 || self.core.retired_roots.load(Ordering::Acquire)&(1<<self.retired_index)==0 {
            return Err(rejected("actual retired signed custody restricted"));
        }
        // A separate actual exclusive owner checks all non-target actors during
        // Q. This observer cannot authorize an effect or skip an actor itself.
        if !self.core.phase.quiescent(){self.core.check()?;}
        if self.core.phase.revoked(){return Err(rejected("retired signed custody revoked"));}
        Ok(())
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
