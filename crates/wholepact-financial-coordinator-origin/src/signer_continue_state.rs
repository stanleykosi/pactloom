//! Private lock-free two-slot restriction state and check-only actual lifetimes.
macro_rules! boundary {
    ($component:ident, $code:ident) => {{
        #[cfg(wholepact_financial_rendered_host_semantic_ci)] {
            use crate::financial_ci_failure_boundary as diagnostic;
            diagnostic::latch(diagnostic::Boundary::$component(diagnostic::$component::$code));
        }
    }};
}

macro_rules! actor_boundary {($stage:ident,$class:ident,$peer:expr)=>{{
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] {use crate::financial_ci_actor_diagnostics as d;d::origin(d::OriginStage::$stage,d::Class::$class,$peer);}
}};}

use crate::{process::PeerLifetime, rejected, Result};
use std::{os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

pub(super) const NEW: u8 = 0;
pub(super) const PREPARING: u8 = 1;
pub(super) const REVIEW: u8 = 2;
pub(super) const ARMED: u8 = 3;
pub(super) const READY: u8 = 4;
pub(super) const ADMITTED: u8 = 5;
const REVOKED: u64 = 1 << 31;
const QUIESCENT:u64=1<<30;
pub(super) const PENDING: u8 = 0;
pub(super) const SENT: u8 = 1;
pub(super) const ABANDONED: u8 = 2;

/// Both target slots and global R share one atomic word. Native A is precisely
/// the successful READY->ADMITTED CAS, never a later driver/relay dequeue.
pub(super) struct Phases {
    word: AtomicU64,
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    host_restriction: Option<crate::host_restriction::CoordinatorHostRestrictionV1>,
}
impl Phases {
    pub(super) fn new() -> Self { Self {
        word: AtomicU64::new(0),
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        host_restriction: None,
    } }
    /// Only the actual C branch can supply this private revoke-on-drop writer.
    /// S and narrow-profile constructors have no shared-memory write owner.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(super) fn coordinator(writer: crate::host_restriction::CoordinatorHostRestrictionV1) -> Self {
        Self { word: AtomicU64::new(0), host_restriction: Some(writer) }
    }
    pub(super) fn phase(&self, slot: usize) -> u8 { ((self.word.load(Ordering::Acquire) >> (slot * 8)) & 0xff) as u8 }
    pub(super) fn revoked(&self) -> bool { self.word.load(Ordering::Acquire) & REVOKED != 0 }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn quiescent(&self)->bool{self.word.load(Ordering::Acquire)&QUIESCENT!=0}
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn snapshot(&self)->u64{self.word.load(Ordering::Acquire)}
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn begin_quiescence(&self,expected:u64)->Result<()>{
        if expected&(REVOKED|QUIESCENT)!=0{return Err(rejected("retirement snapshot already restricted"));}
        self.word.compare_exchange(expected,expected|QUIESCENT,Ordering::AcqRel,Ordering::Acquire)
            .map(|_|()).map_err(|_|rejected("retirement complete phase snapshot changed"))
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn finish_quiescence(&self)->Result<()>{
        let mut old=self.word.load(Ordering::Acquire);
        loop{if old&REVOKED!=0||old&QUIESCENT==0{return Err(rejected("retirement cannot resume restricted workflow"));}
            match self.word.compare_exchange_weak(old,old&!QUIESCENT,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    /// Restriction-only final sample. No actor/phase/clock validation is
    /// replaced by this check; Q is always a fault, never ordinary R.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn positive_send_restricted(&self)->Result<bool>{
        let word=self.word.load(Ordering::Acquire);
        if word&QUIESCENT!=0{return Err(rejected("positive send during exclusive retirement"));}
        Ok(word&REVOKED!=0)
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn source_send_restricted(&self,slot:usize,expected:u8)->Result<bool>{
        if slot>1{return Err(rejected("positive send fixed slot"));}
        let word=self.word.load(Ordering::Acquire);
        if ((word>>(slot*8))&0xff)!=u64::from(expected)||word&QUIESCENT!=0{return Err(rejected("positive send phase changed or quiescent"));}
        Ok(word&REVOKED!=0)
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn witness_send_restricted(&self,slot:usize,expected:u8)->Result<bool>{
        if slot>1{return Err(rejected("positive send fixed slot"));}
        let word=self.word.load(Ordering::Acquire);
        if ((word>>(16+slot*4))&0xf)!=u64::from(expected)||word&QUIESCENT!=0{return Err(rejected("positive send phase changed or quiescent"));}
        Ok(word&REVOKED!=0)
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn history_send_restricted(&self,slot:usize,expected:u8)->Result<bool>{
        if slot>1{return Err(rejected("positive send fixed slot"));}
        let word=self.word.load(Ordering::Acquire);
        if ((word>>(24+slot*3))&7)!=u64::from(expected)||word&QUIESCENT!=0{return Err(rejected("positive send phase changed or quiescent"));}
        Ok(word&REVOKED!=0)
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn signing_send_restricted(&self,slot:usize,expected:u8)->Result<bool>{
        if slot>1{return Err(rejected("positive send fixed slot"));}
        let word=self.word.load(Ordering::Acquire);
        if ((word>>(32+slot*4))&15)!=u64::from(expected)||word&QUIESCENT!=0{return Err(rejected("positive send phase changed or quiescent"));}
        Ok(word&REVOKED!=0)
    }
    pub(super) fn revoke(&self) {
        // EVERY local C restriction path, including errors and Drop, reaches
        // this ordering. Host observes R before local admission can observe R.
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        if let Some(writer) = &self.host_restriction { writer.revoke(); }
        self.word.fetch_or(REVOKED, Ordering::AcqRel);
    }
    /// Fixed observation-only completion. Preserves R and cannot issue a purpose.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_workflow_continue_saved(&self,slot:usize)->Result<()>{
        use crate::financial_workflow_continue::{CONT_ADMITTED,AWAITING_ADMISSION};
        if slot>1{return Err(rejected("not a fixed workflow slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{
            if ((old>>shift)&0xff)!=CONT_ADMITTED as u64{return Err(rejected("Continue completion was not admitted"));}
            let new=(old&!(0xff<<shift))|((AWAITING_ADMISSION as u64)<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// Only S's authenticated ordered Final receive may record this exact
    /// transition after C already admitted it. Preserve R, never issue C's A.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_received_workflow_continue_final(&self,slot:usize)->Result<()>{
        use crate::financial_workflow_continue::{CONT_READY,CONT_ADMITTED};
        if slot>1{return Err(rejected("not a fixed received Continue slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{
            if ((old>>shift)&0xff)!=CONT_READY as u64{return Err(rejected("received Continue Final was not Ready"));}
            let new=(old&!(0xff<<shift))|((CONT_ADMITTED as u64)<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// Fixed post-response observation only, never a fresh Read/key-use grant.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_workflow_admit_saved(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed Admit slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{
            if ((old>>shift)&0xff)!=35{return Err(rejected("Admit completion without admitted attempt"));}
            let new=(old&!(0xff<<shift))|(36<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// An authenticated actual Acquire receipt is an observation, not a new
    /// action. Preserve R, reject quiescence and every other/duplicate phase.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_workflow_acquire_saved(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed Acquire slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{
            if old&QUIESCENT!=0||((old>>shift)&0xff)!=46{return Err(rejected("Acquire completion without exact admitted attempt"));}
            let new=(old&!(0xff<<shift))|(47u64<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// An authenticated actual Activate receipt is an observation, not a new
    /// action. Preserve R, reject quiescence and every other/duplicate phase.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_workflow_activated_saved(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed Activate slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{
            if old&QUIESCENT!=0||((old>>shift)&0xff)!=54{return Err(rejected("Activate completion without exact admitted attempt"));}
            let new=(old&!(0xff<<shift))|(55u64<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// Completion observation of this already-entered purpose, preserving R.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_v3_enrollment_published(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed fresh receipt slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&QUIESCENT!=0||((old>>shift)&0xff)!=133{return Err(rejected("fresh receipt completion without exact admitted effect"));}
            let new=(old&!(0xff<<shift))|(134u64<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// Completion observation of this already-entered purpose, preserving R.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_v3_manifest_published(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed fresh receipt slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&QUIESCENT!=0||((old>>shift)&0xff)!=136{return Err(rejected("fresh receipt completion without exact admitted effect"));}
            let new=(old&!(0xff<<shift))|(137u64<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// Observation after the one entered redisclosure publication and actual response.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_v3_redisclosure_published(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed redisclosure slot"));}
        let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&QUIESCENT!=0||((old>>shift)&0xff)!=142{return Err(rejected("redisclosure completion without exact admitted effect"));}
            let new=(old&!(0xff<<shift))|(143u64<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    /// Immutable observation of an already-entered actual admission publication.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_return_completed(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed exact Return slot"));}let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&QUIESCENT!=0||((old>>shift)&0xff)!=72{return Err(rejected("exact Return observation without exact entered effect"));}let new=(old&!(0xff<<shift))|(73u64<<shift);match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_sign_committed(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed exact signing slot"));}let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&QUIESCENT!=0||((old>>shift)&0xff)!=66{return Err(rejected("exact signing observation without exact entered effect"));}let new=(old&!(0xff<<shift))|(67u64<<shift);match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_v3_admission_published(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed V3 admission slot"));}let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&QUIESCENT!=0||((old>>shift)&0xff)!=156{return Err(rejected("V3 admission observation without exact entered effect"));}let new=(old&!(0xff<<shift))|(157u64<<shift);match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    /// Actual completed V3 observation, only after separate Audit Final has
    /// finished and its exact original immutable result has been retained.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_v3_audited_complete(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("not a fixed V3 Audit slot"));}let shift=slot*8;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&QUIESCENT!=0||((old>>shift)&0xff)!=160{return Err(rejected("completed V3 without finished actual Audit"));}let new=(old&!(0xff<<shift))|(15u64<<shift);match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn witness_phase(&self,slot:usize)->u8 { ((self.word.load(Ordering::Acquire)>>(16+slot*4))&0xf) as u8 }
    /// Two fixed W nibbles share the SAME native A/R CAS word as both S slots.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn witness_step(&self,slot:usize,from:u8,to:u8)->Result<()>{
        if slot>1||from>15||to>15{return Err(rejected("not a fixed financial Witness phase"));}
        let shift=16+slot*4;let mut old=self.word.load(Ordering::Acquire);
        loop{
            if old&(REVOKED|QUIESCENT)!=0||((old>>shift)&0xf)!=from as u64{return Err(rejected("financial Witness phase consumed or restricted"));}
            let new=(old&!(0xf<<shift))|((to as u64)<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}
        }
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn history_phase(&self,slot:usize)->u8{((self.word.load(Ordering::Acquire)>>(24+slot*3))&7)as u8}
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn history_step(&self,slot:usize,from:u8,to:u8)->Result<()>{
        if slot>1||from>7||to>7{return Err(rejected("invalid fixed history phase"));}
        let shift=24+slot*3;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&(REVOKED|QUIESCENT)!=0||((old>>shift)&7)!=from as u64{return Err(rejected("history phase consumed or restricted"));}
            let new=(old&!(7<<shift))|((to as u64)<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn signing_phase(&self,slot:usize)->u8{((self.word.load(Ordering::Acquire)>>(32+slot*4))&15)as u8}
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn signing_step(&self,slot:usize,from:u8,to:u8)->Result<()>{
        if slot>1||from>15||to>15{return Err(rejected("invalid fixed signing phase"));}
        let shift=32+slot*4;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&(REVOKED|QUIESCENT)!=0||((old>>shift)&15)!=from as u64{return Err(rejected("signing phase consumed or restricted"));}
            let new=(old&!(15<<shift))|((to as u64)<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn signing_retirement_step(&self,slot:usize,from:u8,to:u8)->Result<()> {
        if slot>1||!matches!((from,to),(4,5)|(5,6)){return Err(rejected("invalid normal Signing retirement transition"));}
        let shift=32+slot*4;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&REVOKED!=0||old&QUIESCENT==0||((old>>shift)&15)!=from as u64{return Err(rejected("Signing retirement not exclusive current phase"));}
            let new=(old&!(15<<shift))|((to as u64)<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn pair_phase(&self)->u8{((self.word.load(Ordering::Acquire)>>40)&15)as u8}
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn pair_step(&self,from:u8,to:u8)->Result<()> {
        if from>15||to>15{return Err(rejected("invalid Pair phase"));}let mut old=self.word.load(Ordering::Acquire);
        loop{if old&(REVOKED|QUIESCENT)!=0||((old>>40)&15)!=from as u64{return Err(rejected("Pair phase consumed or restricted"));}
            let new=(old&!(15<<40))|((to as u64)<<40);match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn pair_send_restricted(&self,expected:u8)->Result<bool>{
        let word=self.word.load(Ordering::Acquire);if ((word>>40)&15)!=expected as u64{return Err(rejected("Pair send phase mismatch"));}
        if word&QUIESCENT!=0{return Err(rejected("Pair send during retirement"));}Ok(word&REVOKED!=0)
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn normal_phase(&self)->u8{((self.word.load(Ordering::Acquire)>>44)&15)as u8}
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn normal_step(&self,from:u8,to:u8)->Result<()> {
        if !matches!((from,to),(0,1)|(1,2)|(2,3)|(3,4)|(4,5)){return Err(rejected("normal completion step skipped"));}
        let mut old=self.word.load(Ordering::Acquire);
        loop{if old&(REVOKED|QUIESCENT)!=0||((old>>44)&15)!=from as u64{return Err(rejected("normal completion restricted or consumed"));}
            let new=(old&!(15<<44))|((to as u64)<<44);match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    /// Only after actual normal owned History reap. This observation keeps
    /// QUIESCENT and R, and cannot create any native admission or reset a slot.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn observe_history_retired(&self,slot:usize)->Result<()>{
        if slot>1{return Err(rejected("invalid retired History slot"));}
        let shift=24+slot*3;let mut old=self.word.load(Ordering::Acquire);
        loop{if old&QUIESCENT==0||((old>>shift)&7)!=5{return Err(rejected("History retirement observation phase"));}
            let new=(old&!(7<<shift))|(6u64<<shift);
            match self.word.compare_exchange_weak(old,new,Ordering::AcqRel,Ordering::Acquire){Ok(_)=>return Ok(()),Err(actual)=>old=actual}}
    }
    pub(super) fn step(&self, slot: usize, from: u8, to: u8) -> Result<()> {
        if slot > 1 { return Err(rejected("not a fixed Continue slot")); }
        let shift = slot * 8;
        let mut old = self.word.load(Ordering::Acquire);
        loop {
            if old & (REVOKED|QUIESCENT) != 0 || ((old >> shift) & 0xff) != from as u64 {
                return Err(rejected("Continue slot consumed or revoked"));
            }
            let new = (old & !(0xff << shift)) | ((to as u64) << shift);
            match self.word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(()), Err(actual) => old = actual,
            }
        }
    }
}

pub(super) struct CheckedPeer { pidfd: OwnedFd, socket: OwnedFd, #[cfg(wholepact_financial_rendered_host_semantic_ci)] role:crate::process::Role }
impl CheckedPeer {
    pub(super) fn retain(peer: &PeerLifetime, socket: RawFd) -> Result<Self> {
        peer.check_alive()?;
        let result = Self { pidfd: duplicate(peer.fd())?, socket: duplicate(socket)?, #[cfg(wholepact_financial_rendered_host_semantic_ci)] role:peer.role() };
        result.check()?;
        Ok(result)
    }
    pub(super) fn check(&self) -> Result<()> {
        check_pidfd_at(&self.pidfd, true, {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)] {Some(crate::financial_ci_actor_diagnostics::PeerRole::from_role(self.role))}
            #[cfg(not(wholepact_financial_rendered_host_semantic_ci))] {None::<()>}
        })?;
        let mut poll = libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN | libc::POLLRDHUP, revents: 0 };
        let polled = unsafe { libc::poll(&mut poll, 1, 0) };
        if polled < 0
            || poll.revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR | libc::POLLNVAL) != 0
        {
            if polled < 0 || poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 { boundary!(Core, PeerEdgePollError); } else { boundary!(Core, PeerEdgeClosed); }
            #[cfg(wholepact_financial_rendered_host_semantic_ci)] {
                use crate::financial_ci_actor_diagnostics as d;let bad=polled<0||poll.revents&(libc::POLLERR|libc::POLLNVAL)!=0;
                d::origin(if bad{d::OriginStage::PeerEdgePollError}else{d::OriginStage::PeerEdgeClosed},if bad{d::Class::EdgePollError}else{d::Class::EdgeClosed},Some(d::PeerRole::from_role(self.role)));
            }
            return Err(rejected("original Continue edge lost"));
        }
        Ok(())
    }
    pub(super) fn shutdown(&self) { unsafe { libc::shutdown(self.socket.as_raw_fd(), libc::SHUT_RDWR); } }
}
fn duplicate(fd: RawFd) -> Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
fn check_pidfd(fd: &OwnedFd, _index:usize) -> Result<()> { check_pidfd_at(fd, false, {
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] {crate::financial_ci_actor_diagnostics::root_peer(_index)}
 #[cfg(not(wholepact_financial_rendered_host_semantic_ci))] {None::<()>}
}) }
fn check_pidfd_at(fd: &OwnedFd, _peer: bool,
 #[cfg(wholepact_financial_rendered_host_semantic_ci)] _role:Option<crate::financial_ci_actor_diagnostics::PeerRole>,
 #[cfg(not(wholepact_financial_rendered_host_semantic_ci))] _role:Option<()>,
) -> Result<()> {
    let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let polled = unsafe { libc::poll(&mut poll, 1, 0) };
    if polled != 0 || poll.revents != 0 {
        #[cfg(wholepact_financial_rendered_host_semantic_ci)] {
            use crate::financial_ci_failure_boundary as diagnostic;
            diagnostic::latch(diagnostic::Boundary::Core(diagnostic::process_poll_code(_peer,polled,poll.revents)));
        }
        #[cfg(wholepact_financial_rendered_host_semantic_ci)] {use crate::financial_ci_actor_diagnostics as d;
            let bad=polled<0||poll.revents&(libc::POLLERR|libc::POLLNVAL)!=0||poll.revents&(libc::POLLIN|libc::POLLHUP)==0;
            let stage=match(_peer,bad){(true,true)=>d::OriginStage::PeerProcessPollError,(true,false)=>d::OriginStage::PeerProcessExit,(false,true)=>d::OriginStage::RootProcessPollError,(false,false)=>d::OriginStage::RootProcessExit};
            d::origin(stage,if bad{d::Class::ProcessPollError}else{d::Class::ProcessExited},_role);
        }
        return Err(rejected("original Continue process lost"));
    }
    Ok(())
}

pub(super) struct Core {
    pub(super) phase: Phases,
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(super) signer_restriction: Option<crate::host_restriction::SignerSharedRestrictionV1>,
    pub(super) peer: CheckedPeer,
    pub(super) roots: Vec<OwnedFd>,
    pub(super) retired_roots:AtomicU32,
    pub(super) coordinator: Option<PeerLifetime>,
    pub(super) owner_pid: libc::pid_t,
    pub(super) owner_uid: libc::uid_t,
    pub(super) epoch: Instant,
    pub(super) session: Instant,
    pub(super) alive: AtomicBool,
    pub(super) outbound: [AtomicU8; 2],
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) witness_outbound: [AtomicU8; 2],
}
impl Core {
    pub(super) fn check(&self) -> Result<()> {
        let result = (|| {
            let alive = self.alive.load(Ordering::Acquire);
            if !alive || unsafe { libc::getpid() } != self.owner_pid
                || unsafe { libc::geteuid() } != self.owner_uid
            {
                if !alive { boundary!(Core, AlreadyClosedObserved); } else { boundary!(Core, CustodyMismatch); }
                if !alive {actor_boundary!(ActorClosed,AlreadyClosed,None);} else {actor_boundary!(ActorCustody,CustodyMismatch,None);}
                return Err(rejected("original Continue actor custody lost"));
            }
            self.peer.check()?;
            for (i,fd) in self.roots.iter().enumerate() {
                if self.retired_roots.load(Ordering::Acquire)&(1<<i)==0{check_pidfd(fd,i)?;}
            }
            if let Some(c) = &self.coordinator { c.check_alive()?; }
            Ok(())
        })();
        if result.is_err() { self.close(); }
        result
    }
    /// Ordinary action restriction only. Never call this from the admitted
    /// local Continue Final exception or from custody-only checks.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(super) fn check_action_restrictions(&self) -> Result<()> {
        let result = (|| {
            self.check()?;
            crate::channel::require_time(self.session).inspect_err(|_| { boundary!(Core, SessionExpired); actor_boundary!(SessionDeadline,ClockExpired,None); })?;
            let restricted=if self.phase.revoked(){actor_boundary!(ActionRevoked,Restricted,None);true}
                else if self.phase.quiescent(){actor_boundary!(ActionQuiescent,Quiescent,None);true}
                else if self.phase.normal_phase()>=2{actor_boundary!(ActionClosing,Closing,None);true}else{false};
            if restricted { return Err(rejected("original workflow restricted, quiescent or closing")); }
            // Last sample uses the original shared cell, not a queued Cancel.
            if let Some(reader) = &self.signer_restriction { reader.check_current()?; }
            Ok(())
        })();
        if result.is_err() { self.phase.revoke(); }
        result
    }
    /// Only the exclusive private retirement owner calls this while target
    /// exit is expected. Ordinary Core.check NEVER consults an in-flight skip.
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn check_retirement_other_roots(&self,index:usize)->Result<()>{
        if index==0||index>=self.roots.len()||!self.alive.load(Ordering::Acquire)
            ||unsafe{libc::getpid()}!=self.owner_pid||unsafe{libc::geteuid()}!=self.owner_uid
            ||!self.phase.quiescent()||self.phase.revoked(){return Err(rejected("invalid exclusive retirement custody"));}
        self.peer.check()?;crate::channel::require_time(self.session)?;
        for(i,fd)in self.roots.iter().enumerate(){if i!=index&&self.retired_roots.load(Ordering::Acquire)&(1<<i)==0{check_pidfd(fd,i)?;}}
        if let Some(c)=&self.coordinator{c.check_alive()?;}Ok(())
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    pub(super) fn install_retired(&self,proof:&crate::bootstrap::RetiredWitness)->Result<()>{
        let index=proof.index();self.check_retirement_other_roots(index)?;
        if self.retired_roots.fetch_or(1<<index,Ordering::AcqRel)&(1<<index)!=0{return Err(rejected("retirement tombstone duplicated"));}Ok(())
    }
    pub(super) fn close(&self) {
        self.phase.revoke();
        self.alive.store(false, Ordering::Release);
        self.peer.shutdown();
    }
    pub(super) fn pending(&self) -> bool {
        (0..2).any(|i| self.phase.phase(i) == ADMITTED && self.outbound[i].load(Ordering::Acquire) == PENDING)
    }
}

pub(super) fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), libc::GRND_NONBLOCK) } != bytes.len() as isize {
        return Err(rejected("fresh Continue challenge unavailable"));
    }
    Ok(hex::encode(bytes))
}
pub(super) fn hash(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
pub(super) fn wall_ms() -> Result<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| rejected("Continue wall clock before epoch"))?
        .as_millis().try_into().map_err(|_| rejected("Continue wall clock overflow"))
}
pub(super) fn deadline_offset(epoch: Instant, deadline: Instant) -> Result<u64> {
    let ms: u64 = deadline.checked_duration_since(epoch).ok_or_else(|| rejected("Continue deadline underflow"))?
        .as_millis().try_into().map_err(|_| rejected("Continue deadline overflow"))?;
    if ms == 0 || ms > 300_000 { return Err(rejected("Continue deadline outside original session")); }
    Ok(ms) // Rounded DOWN, never a new budget from receive time.
}
pub(super) fn original_deadline(epoch: Instant, ms: u64, ceiling: Instant, now: Instant) -> Result<Instant> {
    if ms == 0 || ms > 300_000 { return Err(rejected("Continue original deadline unsupported")); }
    let result = epoch.checked_add(Duration::from_millis(ms)).ok_or_else(|| rejected("Continue deadline overflow"))?.min(ceiling);
    if result <= now { return Err(rejected("Continue original deadline expired")); }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature="coordinated-financial-workflow-v1")]
    #[test]
    fn signing_history_and_old_slots_share_one_full_width_admission_word(){
        let p=Phases::new();p.step(0,0,36).unwrap();p.witness_step(0,0,6).unwrap();p.history_step(1,0,4).unwrap();
        p.signing_step(0,0,3).unwrap();p.signing_step(1,0,3).unwrap();
        assert_eq!(p.phase(0),36);assert_eq!(p.witness_phase(0),6);assert_eq!(p.history_phase(1),4);
        let snapshot=p.snapshot();p.signing_step(0,3,4).unwrap();assert!(p.begin_quiescence(snapshot).is_err());
        p.begin_quiescence(p.snapshot()).unwrap();assert!(p.signing_step(1,3,4).is_err());assert!(p.history_step(1,4,5).is_err());
        p.revoke();assert!(p.finish_quiescence().is_err());assert!(p.signing_step(1,3,4).is_err());
        assert_eq!(p.signing_phase(0),4);assert_eq!(p.signing_phase(1),3);assert_eq!(p.phase(0),36);
    }

    #[cfg(feature="coordinated-financial-workflow-v1")]
    #[test]
    fn history_reap_observation_preserves_pause_and_revoke_without_new_authority(){
        let phase=Phases::new();phase.history_step(0,0,5).unwrap();
        assert!(phase.observe_history_retired(0).is_err());
        phase.begin_quiescence(phase.snapshot()).unwrap();phase.revoke();
        phase.observe_history_retired(0).unwrap();assert_eq!(phase.history_phase(0),6);
        assert!(phase.quiescent());assert!(phase.revoked());assert!(phase.history_step(1,0,1).is_err());
        assert!(phase.observe_history_retired(0).is_err());assert!(phase.finish_quiescence().is_err());
    }
    #[test]
    fn retirement_quiescence_blocks_all_native_admission_and_never_clears_revoke(){
        let phase=Phases::new();phase.step(0,0,36).unwrap();phase.step(1,0,22).unwrap();phase.witness_step(0,0,6).unwrap();
        phase.begin_quiescence(phase.snapshot()).unwrap();assert!(phase.quiescent());
        assert!(phase.step(1,22,23).is_err());assert!(phase.witness_step(1,0,1).is_err());
        phase.revoke();assert!(phase.finish_quiescence().is_err());assert!(phase.revoked());assert!(phase.quiescent());
        assert_eq!(phase.phase(0),36);assert_eq!(phase.witness_phase(0),6);
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    #[test]
    fn retirement_pause_requires_exact_snapshot_and_successful_resume_preserves_phases(){
        let phase=Phases::new();phase.step(0,0,36).unwrap();
        assert!(phase.begin_quiescence(35).is_err());assert!(!phase.quiescent());
        phase.begin_quiescence(phase.snapshot()).unwrap();assert!(phase.begin_quiescence(phase.snapshot()).is_err());
        phase.finish_quiescence().unwrap();assert_eq!(phase.phase(0),36);assert!(!phase.quiescent());assert!(!phase.revoked());
        assert!(phase.finish_quiescence().is_err());
    }

    #[test]
    fn global_revoke_and_either_final_admission_share_one_atomic_order() {
        let state = Phases::new();
        state.step(0, NEW, READY).unwrap(); state.step(1, NEW, READY).unwrap();
        state.step(0, READY, ADMITTED).unwrap(); state.revoke();
        assert_eq!(state.phase(0), ADMITTED);
        assert!(state.step(1, READY, ADMITTED).is_err());
        assert!(state.step(0, ADMITTED, NEW).is_err());
        let state = Phases::new(); state.step(1, NEW, READY).unwrap(); state.revoke();
        assert!(state.step(1, READY, ADMITTED).is_err());
    }
    #[test]
    fn original_offsets_only_shorten_and_never_restart_a_deadline() {
        let epoch = Instant::now(); let exact = epoch + Duration::from_micros(1_234_567);
        let offset = deadline_offset(epoch, exact).unwrap(); assert_eq!(offset, 1234);
        let restored = original_deadline(epoch, offset, exact, epoch).unwrap();
        assert!(restored <= exact);
        assert!(original_deadline(epoch, offset, exact, restored).is_err());
        assert!(deadline_offset(exact, epoch).is_err());
        assert!(original_deadline(epoch, 300_001, exact, epoch).is_err());
        assert!(original_deadline(epoch, u64::MAX, exact, epoch).is_err());
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    #[test]
    fn positive_send_classifies_only_exact_phase_ordinary_r(){
        let p=Phases::new();p.step(0,0,18).unwrap();p.witness_step(0,0,2).unwrap();p.history_step(0,0,4).unwrap();p.signing_step(0,0,4).unwrap();
        assert!(!p.source_send_restricted(0,18).unwrap());assert!(!p.positive_send_restricted().unwrap());
        p.revoke();let frozen=p.snapshot();
        assert!(p.source_send_restricted(0,18).unwrap());assert!(p.witness_send_restricted(0,2).unwrap());
        assert!(p.history_send_restricted(0,4).unwrap());assert!(p.signing_send_restricted(0,4).unwrap());assert!(p.positive_send_restricted().unwrap());
        assert!(p.source_send_restricted(0,17).is_err());assert!(p.witness_send_restricted(0,3).is_err());
        assert!(p.history_send_restricted(0,3).is_err());assert!(p.signing_send_restricted(0,3).is_err());assert_eq!(p.snapshot(),frozen);
    }
    #[cfg(feature="coordinated-financial-workflow-v1")]
    #[test]
    fn positive_send_quiescence_and_failed_phase_are_never_restriction_success(){
        let p=Phases::new();p.step(0,0,18).unwrap();p.begin_quiescence(p.snapshot()).unwrap();p.revoke();
        assert!(p.positive_send_restricted().is_err());assert!(p.source_send_restricted(0,18).is_err());
        assert!(p.witness_send_restricted(0,0).is_err());assert!(p.history_send_restricted(0,0).is_err());assert!(p.signing_send_restricted(0,0).is_err());
        let p=Phases::new();p.history_step(0,0,4).unwrap();p.revoke();assert!(p.history_step(0,4,5).is_err());
        assert!(p.history_send_restricted(0,4).unwrap());assert_eq!(p.history_phase(0),4);
        assert!(p.history_send_restricted(2,4).is_err());
    }

}

#[cfg(all(test,feature="coordinated-financial-workflow-v1"))]
mod acquired_observation_tests{
    use super::*;
    #[test]
    fn acquired_observation_preserves_r_and_other_slots_without_new_admission(){
        let p=Phases::new();p.step(0,0,46).unwrap();p.step(1,0,45).unwrap();p.signing_step(0,0,4).unwrap();
        p.revoke();let old=p.snapshot();p.observe_workflow_acquire_saved(0).unwrap();
        assert_eq!(p.snapshot()&!255,old&!255);assert_eq!(p.phase(0),47);assert!(p.revoked());
        assert!(p.observe_workflow_acquire_saved(0).is_err());assert!(p.step(1,45,46).is_err());assert!(p.step(0,47,48).is_err());
    }
    #[test]
    fn acquired_observation_rejects_q_wrong_phase_and_foreign_slot(){
        let p=Phases::new();p.step(0,0,46).unwrap();p.begin_quiescence(p.snapshot()).unwrap();p.revoke();
        let old=p.snapshot();assert!(p.observe_workflow_acquire_saved(0).is_err());assert_eq!(p.snapshot(),old);
        let p=Phases::new();p.step(0,0,45).unwrap();p.revoke();assert!(p.observe_workflow_acquire_saved(0).is_err());assert!(p.observe_workflow_acquire_saved(2).is_err());
    }
}

#[cfg(all(test,feature="coordinated-financial-workflow-v1"))]
mod activated_observation_tests{
    use super::*;
    #[test]
    fn activated_result_survives_r_without_authorizing_any_new_action(){
        let p=Phases::new();p.step(0,0,54).unwrap();p.step(1,0,53).unwrap();p.signing_step(0,0,4).unwrap();
        p.revoke();let old=p.snapshot();p.observe_workflow_activated_saved(0).unwrap();
        assert_eq!(p.snapshot()&!255,old&!255);assert_eq!(p.phase(0),55);assert!(p.revoked());
        assert!(p.observe_workflow_activated_saved(0).is_err());assert!(p.step(1,53,54).is_err());assert!(p.step(0,55,56).is_err());
    }
    #[test]
    fn activated_result_rejects_quiescence_wrong_phase_and_foreign_slot(){
        let p=Phases::new();p.step(0,0,54).unwrap();p.begin_quiescence(p.snapshot()).unwrap();p.revoke();
        let old=p.snapshot();assert!(p.observe_workflow_activated_saved(0).is_err());assert_eq!(p.snapshot(),old);
        let p=Phases::new();p.step(0,0,53).unwrap();p.revoke();assert!(p.observe_workflow_activated_saved(0).is_err());assert!(p.observe_workflow_activated_saved(2).is_err());
    }
}
#[cfg(all(test,feature="coordinated-financial-workflow-v1"))]
mod fresh_receipt_observation_tests {
 use super::*;
 #[test]fn fresh_record_completion_preserves_r_without_issuing_next_purpose(){let p=Phases::new();p.step(0,0,133).unwrap();p.revoke();p.observe_v3_enrollment_published(0).unwrap();assert!(p.revoked());assert_eq!(p.phase(0),134);assert!(p.step(0,134,135).is_err());assert!(p.observe_v3_enrollment_published(0).is_err());let p=Phases::new();p.step(1,0,136).unwrap();p.revoke();p.observe_v3_manifest_published(1).unwrap();assert!(p.revoked());assert_eq!(p.phase(1),137);assert!(p.step(1,137,138).is_err());}
 #[test]fn fresh_record_observation_rejects_wrong_slot_phase_and_quiescence(){let p=Phases::new();assert!(p.observe_v3_enrollment_published(2).is_err());assert!(p.observe_v3_manifest_published(0).is_err());p.step(0,0,133).unwrap();p.word.fetch_or(QUIESCENT,Ordering::AcqRel);assert!(p.observe_v3_enrollment_published(0).is_err());}
}

#[cfg(all(test,feature="coordinated-financial-workflow-v1"))]
mod signing_retirement_pair_tests {
 use super::*;
 #[test]fn signing_normal_retirement_requires_exclusive_exact_transition(){let p=Phases::new();p.signing_step(0,0,4).unwrap();assert!(p.signing_retirement_step(0,4,5).is_err());p.begin_quiescence(p.snapshot()).unwrap();assert!(p.signing_retirement_step(0,4,6).is_err());p.signing_retirement_step(0,4,5).unwrap();p.signing_retirement_step(0,5,6).unwrap();assert!(p.signing_retirement_step(0,5,6).is_err());assert!(p.quiescent());}
 #[test]fn revoke_during_normal_reap_cannot_create_retired_phase(){let p=Phases::new();p.signing_step(0,0,4).unwrap();p.begin_quiescence(p.snapshot()).unwrap();p.signing_retirement_step(0,4,5).unwrap();p.revoke();assert!(p.signing_retirement_step(0,5,6).is_err());assert!(p.finish_quiescence().is_err());}
 #[test]fn pair_bits_do_not_alias_signing_history_or_source(){let p=Phases::new();p.step(0,0,67).unwrap();p.signing_step(0,0,6).unwrap();p.history_step(1,0,6).unwrap();p.pair_step(0,1).unwrap();assert_eq!(p.phase(0),67);assert_eq!(p.signing_phase(0),6);assert_eq!(p.history_phase(1),6);assert_eq!(p.pair_phase(),1);p.revoke();assert!(p.pair_send_restricted(1).unwrap());assert!(p.pair_step(1,2).is_err());}
}

#[cfg(all(test,feature="coordinated-financial-workflow-v1"))]
mod normal_completion_tests {
 use super::*;
 #[test]fn normal_finish_never_skips_review_or_duplicates_admission(){let p=Phases::new();assert!(p.normal_step(0,2).is_err());p.normal_step(0,1).unwrap();p.normal_step(1,2).unwrap();assert!(p.normal_step(1,2).is_err());assert_eq!(p.normal_phase(),2);assert_eq!(p.pair_phase(),0);assert_eq!(p.phase(0),0);}
 #[test]fn normal_finish_during_exclusive_retirement_is_rejected(){let p=Phases::new();p.normal_step(0,1).unwrap();p.begin_quiescence(p.snapshot()).unwrap();assert!(p.normal_step(1,2).is_err());}
 #[test]fn revoke_during_actual_root_reaps_prevents_normal_completion(){let p=Phases::new();for i in 0..4{p.normal_step(i,i+1).unwrap();}p.revoke();assert!(p.normal_step(4,5).is_err());assert_eq!(p.normal_phase(),4);}
 #[test]fn normal_state_is_independent_of_pair_and_signed_bits(){let p=Phases::new();p.step(0,0,73).unwrap();p.step(1,0,73).unwrap();p.signing_step(0,0,6).unwrap();p.signing_step(1,0,6).unwrap();p.pair_step(0,4).unwrap();for i in 0..5{p.normal_step(i,i+1).unwrap();}assert_eq!(p.phase(0),73);assert_eq!(p.signing_phase(1),6);assert_eq!(p.pair_phase(),4);assert_eq!(p.normal_phase(),5);}
}

// Concurrent lifetime owners must order the wall sample after the publication
// they compare against. A delayed earlier sample is not a clock rollback. This
// private sampler creates no authority and never renews the original deadline.
pub(crate) fn observe_shared_wall(
    last_wall: &AtomicU64,
    deadline: Instant,
    mut wall_ms: impl FnMut() -> Result<u64>,
) -> Result<Option<u64>> {
    loop {
        if Instant::now() >= deadline {
            actor_boundary!(SharedWallDeadline,ClockExpired,None);
            return Ok(None);
        }
        let prior = last_wall.load(Ordering::Acquire);
        let wall = wall_ms().inspect_err(|_error| {
            #[cfg(wholepact_financial_rendered_host_semantic_ci)]
            crate::financial_ci_actor_diagnostics::origin_io(crate::financial_ci_actor_diagnostics::OriginStage::SharedWallRead,_error,None);
        })?;
        if wall < prior || Instant::now() >= deadline {
            if wall<prior {actor_boundary!(SharedWallRollback,WallRollback,None);} else {actor_boundary!(SharedWallDeadline,ClockExpired,None);}
            return Ok(None);
        }
        if last_wall
            .compare_exchange(prior, wall, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let current=Instant::now() < deadline;
            if !current {actor_boundary!(SharedWallDeadline,ClockExpired,None);}
            return Ok(current.then_some(wall));
        }
        // Another observer published after our load. Resample, rather than
        // rejecting a stale sample or accepting it against a newer high-water.
    }
}
#[cfg(test)]
mod shared_wall_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn reordered_monotonic_samples_resample_without_false_rollback() {
        let last = Arc::new(AtomicU64::new(99));
        let sampled = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let deadline = Instant::now() + Duration::from_secs(60);
        let first = {
            let last = Arc::clone(&last);
            let sampled = Arc::clone(&sampled);
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                let mut initial = true;
                observe_shared_wall(&last, deadline, || {
                    if std::mem::take(&mut initial) {
                        sampled.wait();
                        release.wait();
                        Ok(100)
                    } else {
                        Ok(101)
                    }
                })
            })
        };
        sampled.wait();
        assert_eq!(observe_shared_wall(&last, deadline, || Ok(101)).unwrap(), Some(101));
        release.wait();
        assert_eq!(first.join().unwrap().unwrap(), Some(101));
        assert_eq!(last.load(Ordering::Acquire), 101);
    }

    #[test]
    fn genuine_rollback_and_wall_error_are_not_retried() {
        let last = AtomicU64::new(101);
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut calls = 0;
        assert_eq!(observe_shared_wall(&last, deadline, || {
            calls += 1;
            Ok(100)
        }).unwrap(), None);
        assert_eq!(calls, 1);
        assert_eq!(last.load(Ordering::Acquire), 101);
        assert!(observe_shared_wall(&last, deadline, || Err(rejected("wall unavailable"))).is_err());
        assert_eq!(last.load(Ordering::Acquire), 101);
    }

    #[test]
    fn equal_samples_and_repeated_contention_keep_original_high_water() {
        let last = AtomicU64::new(100);
        let deadline = Instant::now() + Duration::from_secs(60);
        assert_eq!(observe_shared_wall(&last, deadline, || Ok(100)).unwrap(), Some(100));
        let mut calls = 0;
        assert_eq!(observe_shared_wall(&last, deadline, || {
            calls += 1;
            let sample = 100 + calls;
            if calls < 4 {
                // An independently published later sample wins this attempt.
                last.store(sample + 1, Ordering::Release);
            }
            Ok(sample)
        }).unwrap(), Some(104));
        assert_eq!(calls, 4);
        assert_eq!(last.load(Ordering::Acquire), 104);
    }

    #[test]
    fn expired_original_bound_never_samples_or_publishes() {
        let last = AtomicU64::new(100);
        assert_eq!(observe_shared_wall(&last, Instant::now(), || panic!("expired sample")).unwrap(), None);
        assert_eq!(last.load(Ordering::Acquire), 100);
    }

    #[test]
    fn expiry_during_sample_or_contention_does_not_renew_bound() {
        let last = AtomicU64::new(100);
        for contend in [false, true] {
            let deadline = Instant::now() + Duration::from_millis(1);
            let result = observe_shared_wall(&last, deadline, || {
                if contend { last.store(102, Ordering::Release); }
                while Instant::now() < deadline { std::hint::spin_loop(); }
                Ok(101)
            }).unwrap();
            assert_eq!(result, None);
            assert_eq!(last.load(Ordering::Acquire), if contend {102} else {100});
        }
    }
}
