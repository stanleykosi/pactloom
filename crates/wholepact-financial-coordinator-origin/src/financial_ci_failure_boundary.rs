//! Qualification-only first *locally observed* boundaries, never shared R or authority.
//! Latching is allocation/lock/IO-free. Only the original Coordinator process
//! can latch; fork copies cannot impersonate it. No live-session reset exists.
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};

macro_rules! codes {
    ($name:ident { $($code:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum $name { $($code),+ }
        impl $name {
            const NAMES: &'static [&'static str] = &[$(stringify!($code)),+];
        }
    };
}
codes!(Ui {Unobserved, ViewportMissing, FocusLost, Blur, Escape, CloseRequested, InputGuardRejected, ObserverRejected, DriverRestrictionObserved, NativeCheckRejected, FinishedObserved, HostTransportRejected, HostOutputRejected, HostContextChanged, PublicInputRejected, NormalProofRejected, OtherUiRestriction});
codes!(Driver {Unobserved, OriginalTreeCheckError, SessionExpired, EndpointRestrictionObserved, CommandChannelDisconnected, CommandOperationError, CancelSendError, SourceReceiveError, HistoryReceiveError, SigningReceiveError, PairReceiveError, OutcomeChannelFull, OutcomeChannelDisconnected, WorkErrorUnclassified});
codes!(Transport {Unobserved, RestrictedObserved, InputChannelDisconnected, QueueInputRejected, StatusFull, StatusDisconnected, OutputChannelDisconnected, CoreCheckRejected, PtyOutputEof, PtyReadError, PtyWriteError, PtyOwnerMismatch, PtyHostLifetimeLost, PtyModeRejected});
codes!(Core {Unobserved, CustodyMismatch, AlreadyClosedObserved, PeerProcessExit, PeerProcessPollError, PeerEdgeClosed, PeerEdgePollError, RootProcessExit, RootProcessPollError, SessionExpired});

#[derive(Clone, Copy, Debug)]
pub enum Boundary { Ui(Ui), Driver(Driver), Transport(Transport), Core(Core) }
impl Boundary {
    fn parts(self) -> (usize, u8) {
        match self { Self::Ui(v)=>(0,v as u8), Self::Driver(v)=>(1,v as u8),
            Self::Transport(v)=>(2,v as u8), Self::Core(v)=>(3,v as u8) }
    }
}
struct Slots { pid: AtomicI32, codes: [AtomicU8;4] }
impl Slots {
    const fn new() -> Self { Self { pid:AtomicI32::new(0), codes:[const {AtomicU8::new(0)};4] } }
    // Called only by the existing, once-per-original-actor observer entry.
    fn enter(&self, pid:i32, coordinator:bool) {
        if self.pid.load(Ordering::Relaxed)==pid { return; } // Never reset live C.
        self.pid.store(0,Ordering::Relaxed);
        for code in &self.codes { code.store(0,Ordering::Relaxed); }
        if coordinator { self.pid.store(pid,Ordering::Relaxed); }
    }
    fn latch(&self, pid:i32, boundary:Boundary) {
        if self.pid.load(Ordering::Relaxed)!=pid { return; }
        let (slot,code)=boundary.parts();
        if code!=0 { let _=self.codes[slot].compare_exchange(0,code,Ordering::Relaxed,Ordering::Relaxed); }
    }
    fn sample(&self,pid:i32)->Snapshot {
        if self.pid.load(Ordering::Relaxed)!=pid { return Snapshot::default(); }
        Snapshot(self.codes.each_ref().map(|code|code.load(Ordering::Relaxed)))
    }
}
static SLOTS:Slots=Slots::new();
pub(crate) fn enter(coordinator:bool) { SLOTS.enter(unsafe{libc::getpid()},coordinator); }
/// Pure observation: no IO, no error text, no changes to original failure flow.
pub fn latch(boundary:Boundary) { SLOTS.latch(unsafe{libc::getpid()},boundary); }
pub(crate) fn sample()->Snapshot { SLOTS.sample(unsafe{libc::getpid()}) }
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot([u8;4]);
impl Snapshot {
    fn enabled(self)->bool { self.0[0]!=0 || self.0[1]!=0 }
    fn facts(self)->Facts { Facts {version:1,ui:Ui::NAMES[self.0[0] as usize],
        driver:Driver::NAMES[self.0[1] as usize],transport:Transport::NAMES[self.0[2] as usize],core:Core::NAMES[self.0[3] as usize]} }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Facts {pub version:u64,pub ui:&'static str,pub driver:&'static str,pub transport:&'static str,pub core:&'static str}
#[derive(Clone, Copy, Default)]
pub(crate) struct Reporter { last:Snapshot, attempts:u8, failed:bool }
impl Reporter {
    pub(crate) fn flush(&mut self,snapshot:Snapshot,mut append:impl FnMut(Facts)->Result<(),()>) {
        if self.failed || self.attempts>=4 || !snapshot.enabled() || snapshot==self.last { return; }
        // First values cannot change and at least one previously empty slot is
        // filled. Refuse malformed/internal rewrites without emitting them.
        if self.last.0.iter().zip(snapshot.0).any(|(&old,new)|old!=0 && old!=new) { return; }
        self.last=snapshot;
        self.attempts+=1; // Attempt precedes IO; uncertain append is NEVER retried.
        if append(snapshot.facts()).is_err() { self.failed=true; }
    }
}

// Classification only: the caller retains its exact original poll predicate.
// Invalid descriptor/poll errors are not evidence that an actor exited.
pub(crate) fn process_poll_code(peer:bool,polled:i32,revents:i16)->Core {
    let error=polled<0 || revents&(libc::POLLERR|libc::POLLNVAL)!=0
        || revents&(libc::POLLIN|libc::POLLHUP)==0;
    match (peer,error) { (true,true)=>Core::PeerProcessPollError,(true,false)=>Core::PeerProcessExit,
        (false,true)=>Core::RootProcessPollError,(false,false)=>Core::RootProcessExit }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state()->Slots { let s=Slots::new();s.enter(11,true);s }
    #[test] fn first_wins_and_components_are_independent() {
        let s=state();s.latch(11,Boundary::Ui(Ui::FocusLost));s.latch(11,Boundary::Ui(Ui::Escape));
        s.latch(11,Boundary::Driver(Driver::WorkErrorUnclassified));s.latch(11,Boundary::Core(Core::PeerEdgeClosed));
        let f=s.sample(11).facts();assert_eq!(f.ui,"FocusLost");assert_eq!(f.driver,"WorkErrorUnclassified");assert_eq!(f.core,"PeerEdgeClosed");
    }
    #[test] fn foreign_and_inherited_actor_cannot_latch_or_sample() {
        let s=state();s.latch(12,Boundary::Ui(Ui::Escape));assert_eq!(s.sample(11),Snapshot::default());
        s.latch(11,Boundary::Ui(Ui::Escape));assert_eq!(s.sample(12),Snapshot::default());
        s.enter(12,false);s.latch(12,Boundary::Ui(Ui::Escape));assert_eq!(s.sample(12),Snapshot::default());
    }
    #[test] fn repeated_original_entry_never_resets() {let s=state();s.latch(11,Boundary::Ui(Ui::Escape));s.enter(11,true);assert_eq!(s.sample(11).facts().ui,"Escape");}
    #[test] fn unobserved_cannot_clear_first_value() {let s=state();s.latch(11,Boundary::Ui(Ui::Escape));s.latch(11,Boundary::Ui(Ui::Unobserved));assert_eq!(s.sample(11).facts().ui,"Escape");}
    #[test] fn no_observation_for_no_failure_or_core_transport_only() {
        let s=state();let mut r=Reporter::default();r.flush(s.sample(11),|_|panic!("normal"));
        s.latch(11,Boundary::Core(Core::AlreadyClosedObserved));s.latch(11,Boundary::Transport(Transport::RestrictedObserved));
        r.flush(s.sample(11),|_|panic!("normal cleanup"));assert_eq!(r.attempts,0);
    }
    #[test] fn driver_failure_alone_enables_record() {let s=state();s.latch(11,Boundary::Driver(Driver::SourceReceiveError));let mut r=Reporter::default();let mut count=0;r.flush(s.sample(11),|f|{count+=1;assert_eq!(f.ui,"Unobserved");Ok(())});assert_eq!(count,1);}
    #[test] fn four_monotone_records_max_and_duplicates_suppressed() {
        let s=state();let mut r=Reporter::default();let mut records=Vec::new();
        for b in [Boundary::Ui(Ui::Escape),Boundary::Driver(Driver::SessionExpired),Boundary::Transport(Transport::PtyOutputEof),Boundary::Core(Core::PeerProcessExit)] {
            s.latch(11,b);r.flush(s.sample(11),|f|{records.push(f);Ok(())});r.flush(s.sample(11),|_|panic!("duplicate"));
        }
        assert_eq!(records.len(),4);assert_eq!(r.attempts,4);
    }
    #[test] fn uncertain_append_disables_every_later_retry() {
        let s=state();s.latch(11,Boundary::Ui(Ui::Escape));let mut r=Reporter::default();let mut original_cleanup=0;
        r.flush(s.sample(11),|_|Err(()));original_cleanup+=1;
        s.latch(11,Boundary::Driver(Driver::WorkErrorUnclassified));r.flush(s.sample(11),|_|panic!("retry"));
        assert_eq!(original_cleanup,1);assert_eq!(r.attempts,1);assert!(r.failed);
    }
    #[test] fn rewrites_are_never_emitted() {let mut r=Reporter::default();r.flush(Snapshot([1,0,0,0]),|_|Ok(()));r.flush(Snapshot([2,1,0,0]),|_|panic!("rewrite"));assert_eq!(r.attempts,1);}
    #[test] fn concurrent_latches_never_rewrite_a_slot() {
        let s=std::sync::Arc::new(state());let mut threads=Vec::new();
        for code in [Ui::Escape,Ui::FocusLost,Ui::CloseRequested,Ui::OtherUiRestriction] {
            let s=s.clone();threads.push(std::thread::spawn(move||{for _ in 0..1000{s.latch(11,Boundary::Ui(code));}}));
        }
        for thread in threads {thread.join().unwrap();}
        let first=s.sample(11);assert_ne!(first.0[0],0);
        s.latch(11,Boundary::Ui(Ui::ObserverRejected));assert_eq!(s.sample(11),first);
    }
    #[test] fn process_poll_invalid_descriptor_is_not_actor_exit() {
        for peer in [false,true] {
            for (polled,bits) in [(-1,0),(1,libc::POLLERR),(1,libc::POLLNVAL),(1,libc::POLLIN|libc::POLLNVAL),(1,0)] {
                assert_eq!(process_poll_code(peer,polled,bits),if peer{Core::PeerProcessPollError}else{Core::RootProcessPollError});
            }
            for bits in [libc::POLLIN,libc::POLLHUP,libc::POLLIN|libc::POLLHUP] {
                assert_eq!(process_poll_code(peer,1,bits),if peer{Core::PeerProcessExit}else{Core::RootProcessExit});
            }
        }
    }
    #[test] fn all_codes_are_fixed_ascii_and_nonempty() {for names in [Ui::NAMES,Driver::NAMES,Transport::NAMES,Core::NAMES] {assert_eq!(names[0],"Unobserved");for name in names {assert!(name.bytes().all(|b|b.is_ascii_alphanumeric()));}}}
}
