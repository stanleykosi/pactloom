//! Opaque received SourceEntry/Read values and restriction-only original custody.
//! Constructors are crate-private and used only by the genuine full-role receive.
use crate::{rejected, Result, financial_workflow_channel::{EntryOffer, SignerFinancialReadPresentationV1,
    SignerSourceEntryPresentationV1}, financial_workflow_clock::FullWorkflowClocksV1,
    signer_continue_state::{self as state, Core}, source_entry_envelope::{Envelope,RecipientKey}};
use std::{sync::{Arc,atomic::{AtomicU64,Ordering}},time::{Duration,Instant}};
use zeroize::Zeroizing;

pub(super) const V3_HELD:u8=0;
pub(super) const ENTRY_PREPARING:u8=16;
pub(super) const ENTRY_REVIEW:u8=17;
pub(super) const ENTRY_ADMITTED:u8=18;
pub(super) const SOURCE_RETAINED:u8=19;
pub(super) const READ_REVIEW:u8=20;
pub(super) const READ_ADMITTED:u8=21;
pub(super) const HISTORY_RETAINED:u8=22;

pub(super) struct EntryReviewed {
    pub core:Arc<Core>, pub clocks:FullWorkflowClocksV1, pub wire:EntryOffer,
    pub original_source:Instant, pub original_entry:Instant, pub ceiling:Instant,
    last_wall:AtomicU64,
}
impl EntryReviewed {
    pub(super) fn new(core:Arc<Core>,clocks:FullWorkflowClocksV1,wire:EntryOffer,source:Instant,entry:Instant)->Result<Arc<Self>> {
        wire.validate()?;let now=Instant::now();let wall=state::wall_ms()?;
        let p=&wire.presentation;
        let native=clocks.restrict_received(&wire.start.profile,wire.start.native_ceiling_ms,clocks.supervision(),now)?;
        let encoded_source=clocks.restrict_received(&wire.start.profile,p.source_ceiling_ms,source,now)?;
        let encoded_entry=clocks.restrict_received(&wire.start.profile,p.entry_ceiling_ms,entry,now)?;
        let ceiling=native.min(encoded_source).min(encoded_entry).min(wall_ceiling(now,wall,p.facts.reviewed_at_ms,p.facts.expires_at_ms)?);
        let reviewed=Arc::new(Self{core,clocks,wire,original_source:source,original_entry:entry,ceiling,last_wall:AtomicU64::new(wall)});
        reviewed.check_action()?;Ok(reviewed)
    }
    pub(super) fn slot(&self)->usize{self.wire.start.role.index()}
    pub(super) fn check_custody(&self)->Result<()> { self.observe_custody().map(|_|()) }
    fn observe_custody(&self)->Result<u64> {
        let result=(||{
            self.core.check()?;let now=Instant::now();let wall=state::wall_ms()?;
            let prior=self.last_wall.fetch_max(wall,Ordering::AcqRel);
            if now>=self.original_source||now>=self.clocks.supervision()||wall<prior||wall<self.wire.presentation.facts.reviewed_at_ms
                ||wall>=self.wire.presentation.facts.source_expires_at_ms{return Err(rejected("original financial custody expired"));}Ok(wall)
        })();if result.is_err(){self.core.phase.revoke();}result
    }
    pub(super) fn check_action(&self)->Result<()> {
        let result=(||{let wall=self.observe_custody()?;
            if self.core.phase.revoked()||Instant::now()>=self.original_entry||Instant::now()>=self.ceiling
                ||wall>=self.wire.presentation.facts.expires_at_ms
            {return Err(rejected("SourceEntry restriction observed"));}Ok(())})();
        if result.is_err(){self.core.phase.revoke();}result
    }
}
pub(super) fn wall_ceiling(now:Instant,wall:u64,start:u64,end:u64)->Result<Instant>{
    if wall<start||wall>=end{return Err(rejected("original workflow wall bound elapsed"));}
    now.checked_add(Duration::from_millis((end-wall).min(120_000))).ok_or_else(||rejected("workflow wall cap overflow"))
}
pub struct SignerSourceEntryOfferV1 {pub(super) entry:Arc<EntryReviewed>,pub(super) consumed:bool}
impl SignerSourceEntryOfferV1 {
    pub fn presentation(&self)->&SignerSourceEntryPresentationV1{&self.entry.wire.presentation}
    pub fn request_digest(&self)->Result<String>{self.entry.wire.crypto.request_digest()}
    pub fn native_deadline(&self)->Instant{self.entry.ceiling}
    pub fn check_current(&self)->Result<()>{
        self.entry.check_action()?;
        if self.entry.core.phase.phase(self.entry.slot())!=ENTRY_REVIEW{return Err(rejected("SourceEntry offer is no longer pending"));}Ok(())
    }
}
impl Drop for SignerSourceEntryOfferV1{fn drop(&mut self){if !self.consumed{self.entry.core.phase.revoke();}}}
pub struct SignerSourceEntryOutboundV1 {
    pub(super) entry:Arc<EntryReviewed>,pub(super) password:Option<Zeroizing<Vec<u8>>>,pub(super) consumed:bool,
}
impl Drop for SignerSourceEntryOutboundV1{fn drop(&mut self){if !self.consumed{self.entry.core.phase.revoke();}}}

/// Only actual S authenticated receive constructs these matching values. Input
/// is not authority; Final remains restrictive through decrypt/KDF/full audit.
pub struct SignerSourceEntryFinalV1 {pub(super) entry:Arc<EntryReviewed>,pub(super) consumed:bool}
pub struct SignerSourceEntryInputV1 {
    pub(super) entry:Arc<EntryReviewed>,pub(super) recipient:Option<RecipientKey>,
    pub(super) envelope:Option<Envelope>,pub(super) consumed:bool,
}
impl SignerSourceEntryFinalV1 {
    pub fn selection_digest(&self)->&str{&self.entry.wire.presentation.facts.selection_digest}
    pub fn presentation_digest(&self)->&str{&self.entry.wire.presentation.presentation_digest}
    pub fn original_host_process_instance(&self)->&str{&self.entry.wire.presentation.facts.original_host_process_instance}
    pub fn original_entry_deadline(&self)->Instant{self.entry.original_entry}
    pub fn original_source_deadline(&self)->Instant{self.entry.original_source}
    pub fn check_current(&self)->Result<()> {
        self.entry.check_action()?;
        if self.entry.core.phase.phase(self.entry.slot())!=ENTRY_ADMITTED{return Err(rejected("SourceEntry Final consumed"));}Ok(())
    }
    /// The actual source opener calls only after successful complete audit and
    /// one final restriction check. This phase advance proves protocol state,
    /// not the audit itself, and gives no permission to perform another action.
    pub fn into_original_custody_lifetime(mut self)->Result<SignerOriginalCustodyLifetimeV1>{
        self.check_current()?;self.entry.core.phase.step(self.entry.slot(),ENTRY_ADMITTED,SOURCE_RETAINED)?;
        self.consumed=true;Ok(SignerOriginalCustodyLifetimeV1{entry:Arc::clone(&self.entry)})
    }
}
impl Drop for SignerSourceEntryFinalV1{fn drop(&mut self){if !self.consumed{self.entry.core.phase.revoke();}}}
impl SignerSourceEntryInputV1 {
    pub fn open(mut self,final_action:&SignerSourceEntryFinalV1)->Result<Zeroizing<Vec<u8>>>{
        // Consume recipient/input before all fallible work. No returned retry.
        let recipient=self.recipient.take();let envelope=self.envelope.take();self.consumed=true;
        let result=(||{
            if !Arc::ptr_eq(&self.entry,&final_action.entry){return Err(rejected("foreign SourceEntry input/Final"));}
            final_action.check_current()?;
            let plaintext=recipient.ok_or_else(||rejected("SourceEntry key consumed"))?.open(&self.entry.wire.crypto,
                envelope.ok_or_else(||rejected("SourceEntry input consumed"))?)?;
            final_action.check_current()?;Ok(plaintext)
        })();if result.is_err(){self.entry.core.phase.revoke();}result
    }
}
impl Drop for SignerSourceEntryInputV1{fn drop(&mut self){if !self.consumed{self.entry.core.phase.revoke();}}}

/// Restriction-only ORIGINAL-CUSTODY observer, not action currentness or a grant.
/// Ordinary R alone does not recall an already-admitted later Continue effect.
/// All new purpose issuers and Entry/Read Final still check R independently.
pub struct SignerOriginalCustodyLifetimeV1 {entry:Arc<EntryReviewed>}
impl SignerOriginalCustodyLifetimeV1 {pub fn check_current(&self)->Result<()>{self.entry.check_custody()}}

pub(super) struct ReadReviewed {
    pub entry:Arc<EntryReviewed>,pub wire:SignerFinancialReadPresentationV1,
    pub original_read:Instant,pub ceiling:Instant,last_wall:AtomicU64,
}
impl ReadReviewed {
    pub(super) fn new(entry:Arc<EntryReviewed>,wire:SignerFinancialReadPresentationV1,original_read:Instant,original_source:Instant)->Result<Arc<Self>> {
        wire.validate()?;
        if original_source!=entry.original_source||!wire.matches_entry(&entry.wire.presentation){return Err(rejected("Read substituted original source"));}
        let now=Instant::now();let wall=state::wall_ms()?;
        let bound=entry.clocks.restrict_received(&wire.actor.profile,wire.read_ceiling_ms,original_read,now)?;
        let ceiling=bound.min(entry.original_source).min(wall_ceiling(now,wall,wire.facts.reviewed_at_ms,wire.facts.expires_at_ms)?);
        let read=Arc::new(Self{entry,wire,original_read,ceiling,last_wall:AtomicU64::new(wall)});read.check()?;Ok(read)
    }
    pub(super) fn check(&self)->Result<()> {
        let result=(||{
            let wall=self.entry.observe_custody()?;
            let prior=self.last_wall.fetch_max(wall,Ordering::AcqRel);
            if self.entry.core.phase.revoked()||Instant::now()>=self.original_read||Instant::now()>=self.ceiling
                ||wall<prior||wall<self.wire.facts.reviewed_at_ms||wall>=self.wire.facts.expires_at_ms
            {return Err(rejected("initial Read restriction observed"));}Ok(())})();
        if result.is_err(){self.entry.core.phase.revoke();}result
    }
}
pub struct SignerFinancialReadTicketV1{pub(super) read:Arc<ReadReviewed>,pub(super) consumed:bool}
impl SignerFinancialReadTicketV1{
    pub fn presentation(&self)->&SignerFinancialReadPresentationV1{&self.read.wire}
    pub fn native_deadline(&self)->Instant{self.read.ceiling}
    pub fn check_current(&self)->Result<()>{
        self.read.check()?;
        if self.read.entry.core.phase.phase(self.read.entry.slot())!=READ_REVIEW{return Err(rejected("initial Read ticket is no longer pending"));}Ok(())
    }
}
impl Drop for SignerFinancialReadTicketV1{fn drop(&mut self){if !self.consumed{self.read.entry.core.phase.revoke();}}}
pub struct SignerFinancialReadOutboundV1{pub(super) read:Arc<ReadReviewed>,pub(super) consumed:bool}
impl Drop for SignerFinancialReadOutboundV1{fn drop(&mut self){if !self.consumed{self.read.entry.core.phase.revoke();}}}
pub struct SignerFinancialReadFinalV1{pub(super) read:Arc<ReadReviewed>,pub(super) consumed:bool}
impl SignerFinancialReadFinalV1 {
    pub fn presentation(&self)->&SignerFinancialReadPresentationV1{&self.read.wire}
    pub fn read_digest(&self)->&str{&self.read.wire.facts.read_digest}
    pub fn presentation_digest(&self)->&str{&self.read.wire.presentation_digest}
    pub fn original_host_process_instance(&self)->&str{&self.read.wire.facts.original_host_process_instance}
    pub fn original_read_deadline(&self)->Instant{self.read.original_read}
    pub fn original_source_deadline(&self)->Instant{self.read.entry.original_source}
    pub fn check_current(&self)->Result<()> {
        self.read.check()?;
        if self.read.entry.core.phase.phase(self.read.entry.slot())!=READ_ADMITTED{return Err(rejected("Read Final consumed"));}Ok(())
    }
    /// Call only after the actual checked history AND complete immutable local
    /// Continue preparation authorized by wire-v2 Read. This advances state, not
    /// proof of either operation; actual authenticated history/ticket stay S.
    pub fn finish_read(mut self)->Result<()> {
        self.check_current()?;self.read.entry.core.phase.step(self.read.entry.slot(),READ_ADMITTED,HISTORY_RETAINED)?;
        self.consumed=true;Ok(())
    }
}
impl Drop for SignerFinancialReadFinalV1{fn drop(&mut self){if !self.consumed{self.read.entry.core.phase.revoke();}}}

#[cfg(test)]mod tests{
    use super::*;use crate::signer_continue_state::Phases;
    #[test]
    fn entry_and_read_completion_stay_interruptible_after_native_admission(){
        let phases=Phases::new();phases.step(0,V3_HELD,ENTRY_PREPARING).unwrap();phases.step(0,ENTRY_PREPARING,ENTRY_REVIEW).unwrap();
        phases.step(0,ENTRY_REVIEW,ENTRY_ADMITTED).unwrap();phases.revoke();
        assert!(phases.step(0,ENTRY_ADMITTED,SOURCE_RETAINED).is_err());
        let phases=Phases::new();phases.step(1,V3_HELD,SOURCE_RETAINED).unwrap();phases.step(1,SOURCE_RETAINED,READ_REVIEW).unwrap();
        phases.step(1,READ_REVIEW,READ_ADMITTED).unwrap();phases.revoke();assert!(phases.step(1,READ_ADMITTED,HISTORY_RETAINED).is_err());
    }
    #[test]
    fn one_way_full_phases_do_not_rearm_a_consumed_entry_or_read(){
        let phases=Phases::new();for(from,to)in[(V3_HELD,ENTRY_PREPARING),(ENTRY_PREPARING,ENTRY_REVIEW),(ENTRY_REVIEW,ENTRY_ADMITTED),
            (ENTRY_ADMITTED,SOURCE_RETAINED),(SOURCE_RETAINED,READ_REVIEW),(READ_REVIEW,READ_ADMITTED),(READ_ADMITTED,HISTORY_RETAINED)]{
            phases.step(0,from,to).unwrap();assert!(phases.step(0,from,to).is_err());}
        assert_eq!(phases.phase(0),HISTORY_RETAINED);
        assert!(phases.step(0,V3_HELD,ENTRY_PREPARING).is_err());
        phases.revoke();assert!(phases.step(1,V3_HELD,ENTRY_PREPARING).is_err());
    }
    #[test]
    fn wall_ceiling_rejects_elapsed_and_regressed_bounds_without_renewal(){
        let now=Instant::now();assert!(wall_ceiling(now,999,1000,2000).is_err());assert!(wall_ceiling(now,2000,1000,2000).is_err());
        assert_eq!(wall_ceiling(now,1500,1000,2000).unwrap(),now+Duration::from_millis(500));
        assert_eq!(wall_ceiling(now,1000,1000,200000).unwrap(),now+Duration::from_secs(120));
    }
}
