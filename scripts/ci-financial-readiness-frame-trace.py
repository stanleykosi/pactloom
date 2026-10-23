#!/usr/bin/env python3
"""Source-extracted readiness setup and ordinary authenticated frame kernels.

Only time, libc poll/recvmsg/ancillary carriers, stream and peer are inert. The
budget gates, setup loop, transfer deadline, complete receiver/parser, currentness
ordering and byte cap are literal production source. This is not a socket,
credential, process-custody, authority, or end-to-end runtime witness.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def block(source, marker):
    start = source.index(marker)
    pos = source.index('{', start) + 1
    depth = 1
    token = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]', re.S)
    while depth:
        hit = token.search(source, pos)
        if hit is None:
            raise ValueError(marker)
        depth += (hit.group() == '{') - (hit.group() == '}')
        pos = hit.end()
    return source[start:pos]


PREFIX = r'''#![allow(dead_code,unused_imports,non_camel_case_types,non_snake_case)]
extern crate std as real_std;
use real_std::{cell::RefCell,collections::VecDeque,ops::{Add,Deref,DerefMut},time::Duration};
use crate::fake_std as std;
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct Instant(u64);
impl Instant{
 fn now()->Self{STATE.with(|s|Self(s.borrow().now))}
 fn checked_duration_since(self,earlier:Self)->Option<Duration>{self.0.checked_sub(earlier.0).map(Duration::from_millis)}
}
impl Add<Duration> for Instant{type Output=Self;fn add(self,d:Duration)->Self{Self(self.0+d.as_millis() as u64)}}
mod fake_std{
 pub use crate::real_std::{mem,ptr,result};
 pub mod io{
  #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum ErrorKind{Interrupted,WouldBlock,TimedOut,Other}
  #[derive(Clone,Debug,PartialEq,Eq)]pub struct Error(pub ErrorKind);
  impl Error{pub fn last_os_error()->Self{crate::STATE.with(|s|Self(s.borrow().last_io))}pub fn kind(&self)->ErrorKind{self.0}}
 }
}
#[derive(Clone,Debug,PartialEq,Eq)]enum Error{Limit,InvalidData,Authentication,Permission,Io(std::io::Error),CurrentSentinel,PeerSentinel}
type Result<T>=real_std::result::Result<T,Error>;
#[derive(Debug)]struct Zeroizing<T>(T);impl<T> Zeroizing<T>{fn new(v:T)->Self{Self(v)}}
impl<T>Deref for Zeroizing<T>{type Target=T;fn deref(&self)->&T{&self.0}}
impl<T>DerefMut for Zeroizing<T>{fn deref_mut(&mut self)->&mut T{&mut self.0}}
const MAX_FRAME:usize=2_100_000;
#[derive(Clone,Copy)]struct Poll{advance:u64,ready:i32,flags:i16,error:std::io::ErrorKind}
impl Poll{fn readable(advance:u64)->Self{Self{advance,ready:1,flags:libc::POLLIN,error:std::io::ErrorKind::Other}}fn idle(advance:u64)->Self{Self{advance,ready:0,flags:0,error:std::io::ErrorKind::Other}}}
#[derive(Clone,Copy,Debug)]enum Ancillary{Good,Missing,Wrong,Duplicate,Unexpected,Truncated}
#[derive(Clone)]struct Read{advance:u64,bytes:Vec<u8>,error:Option<std::io::ErrorKind>,ancillary:Ancillary}
impl Read{fn bytes(advance:u64,b:&[u8])->Self{Self{advance,bytes:b.to_vec(),error:None,ancillary:Ancillary::Good}}fn error(advance:u64,k:std::io::ErrorKind)->Self{Self{advance,bytes:vec![],error:Some(k),ancillary:Ancillary::Good}}}
struct State{now:u64,polls:VecDeque<Poll>,reads:VecDeque<Read>,trace:Vec<&'static str>,waits:Vec<i32>,timeouts:Vec<Duration>,bytes:usize,current:usize,peer:usize,fail_current:Option<usize>,fail_peer:Option<usize>,timeout_error:bool,last_io:std::io::ErrorKind}
impl Default for State{fn default()->Self{Self{now:0,polls:vec![Poll::readable(0)].into(),reads:vec![Read::bytes(0,b"ok\n")].into(),trace:vec![],waits:vec![],timeouts:vec![],bytes:0,current:0,peer:0,fail_current:None,fail_peer:None,timeout_error:false,last_io:std::io::ErrorKind::Other}}}
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
fn reset(){STATE.with(|s|*s.borrow_mut()=State::default());}
fn edit(f:impl FnOnce(&mut State)){STATE.with(|s|f(&mut s.borrow_mut()));}
fn snapshot()->(Vec<&'static str>,usize,usize,usize){STATE.with(|s|{let s=s.borrow();(s.trace.clone(),s.bytes,s.polls.len(),s.reads.len())})}
fn current()->Result<()>{STATE.with(|s|{let mut s=s.borrow_mut();s.trace.push("current");s.current+=1;if s.fail_current==Some(s.current){Err(Error::CurrentSentinel)}else{Ok(())}})}
struct PeerProcess;impl PeerProcess{
 fn check_alive(&self)->Result<()>{STATE.with(|s|{let mut s=s.borrow_mut();s.trace.push("peer");s.peer+=1;if s.fail_peer==Some(s.peer){Err(Error::PeerSentinel)}else{Ok(())}})}
 fn pid(&self)->u32{7}fn uid(&self)->u32{8}
}
struct UnixStream;impl UnixStream{
 fn as_raw_fd(&self)->i32{9}
 fn set_read_timeout(&self,d:Option<Duration>)->real_std::result::Result<(),std::io::Error>{STATE.with(|s|{let mut s=s.borrow_mut();s.trace.push("timeout");s.timeouts.push(d.unwrap());if s.timeout_error{Err(std::io::Error(std::io::ErrorKind::Other))}else{Ok(())}})}
}
// Fake libc only copies public scripted bytes into the production parser's
// buffers. No actual poll/recvmsg/close/socket or operating-system credential.
mod libc{
 pub type c_int=i32;pub type c_uint=u32;
 pub const POLLIN:i16=1;pub const POLLERR:i16=8;pub const POLLHUP:i16=16;pub const POLLNVAL:i16=32;
 pub const SOL_SOCKET:i32=1;pub const SCM_CREDENTIALS:i32=2;pub const SCM_RIGHTS:i32=3;
 pub const MSG_CMSG_CLOEXEC:i32=4;pub const MSG_TRUNC:i32=8;pub const MSG_CTRUNC:i32=16;
 #[repr(C)]pub struct pollfd{pub fd:i32,pub events:i16,pub revents:i16}
 #[repr(C)]pub struct iovec{pub iov_base:*mut core::ffi::c_void,pub iov_len:usize}
 #[repr(C)]pub struct msghdr{pub msg_iov:*mut iovec,pub msg_iovlen:usize,pub msg_control:*mut core::ffi::c_void,pub msg_controllen:usize,pub msg_flags:i32}
 #[repr(C)]pub struct cmsghdr{pub cmsg_len:usize,pub cmsg_level:i32,pub cmsg_type:i32}
 #[repr(C)]#[derive(Clone,Copy)]pub struct ucred{pub pid:i32,pub uid:u32,pub gid:u32}
 pub unsafe fn poll(p:*mut pollfd,n:usize,wait:i32)->i32{assert_eq!(n,1);assert!((1..=100).contains(&wait));let v=crate::STATE.with(|s|{let mut s=s.borrow_mut();s.trace.push("poll");s.waits.push(wait);let p=s.polls.pop_front().expect("inert poll script exhausted");s.now+=p.advance;s.last_io=p.error;p});(*p).revents=v.flags;v.ready}
 pub unsafe fn recvmsg(fd:i32,msg:*mut msghdr,flags:i32)->isize{assert_eq!(fd,9);assert_eq!(flags,MSG_CMSG_CLOEXEC);let r=crate::STATE.with(|s|{let mut s=s.borrow_mut();s.trace.push("recv");let r=s.reads.pop_front().expect("inert recv script exhausted");s.now+=r.advance;if let Some(k)=r.error{s.last_io=k}else{s.bytes+=r.bytes.len()}r});if r.error.is_some(){return -1}let m=&mut *msg;assert_eq!(m.msg_iovlen,1);let i=&*m.msg_iov;assert!(r.bytes.len()<=i.iov_len);core::ptr::copy_nonoverlapping(r.bytes.as_ptr(),i.iov_base.cast::<u8>(),r.bytes.len());
  m.msg_flags=if matches!(r.ancillary,crate::Ancillary::Truncated){MSG_CTRUNC}else{0};
  let count=match r.ancillary{crate::Ancillary::Missing=>0,crate::Ancillary::Duplicate=>2,_=>1};assert!(m.msg_controllen>=count*40);m.msg_controllen=count*40;
  for index in 0..count{let h=m.msg_control.cast::<u8>().add(index*40).cast::<cmsghdr>();let unexpected=matches!(r.ancillary,crate::Ancillary::Unexpected);core::ptr::write(h,cmsghdr{cmsg_len:CMSG_LEN(if unexpected{4}else{12}) as usize,cmsg_level:SOL_SOCKET,cmsg_type:if unexpected{SCM_RIGHTS}else{SCM_CREDENTIALS}});if unexpected{core::ptr::write_unaligned(CMSG_DATA(h).cast::<i32>(),42);}else{core::ptr::write_unaligned(CMSG_DATA(h).cast::<ucred>(),ucred{pid:if matches!(r.ancillary,crate::Ancillary::Wrong){70}else{7},uid:8,gid:0});}}
  r.bytes.len() as isize
 }
 pub unsafe fn CMSG_FIRSTHDR(m:*const msghdr)->*mut cmsghdr{let m=&*m;if m.msg_controllen==0{core::ptr::null_mut()}else{m.msg_control.cast()}}
 pub unsafe fn CMSG_NXTHDR(m:*const msghdr,h:*const cmsghdr)->*mut cmsghdr{let m=&*m;let offset=(h as usize)-(m.msg_control as usize)+40;if offset<m.msg_controllen{m.msg_control.cast::<u8>().add(offset).cast()}else{core::ptr::null_mut()}}
 pub fn CMSG_LEN(n:c_uint)->c_uint{crate::real_std::mem::size_of::<cmsghdr>() as u32+n}
 pub unsafe fn CMSG_DATA(h:*const cmsghdr)->*mut u8{(h as *mut u8).add(crate::real_std::mem::size_of::<cmsghdr>())}
 pub unsafe fn close(fd:i32)->i32{assert_eq!(fd,42);crate::edit(|s|s.trace.push("close-inert-fd"));0}
}
'''

TESTS = r'''
fn ordinary(deadline:u64)->real_std::result::Result<Zeroizing<Vec<u8>>,ObservedFrameError>{read_frame_capped_checked_observed_until(&UnixStream,&PeerProcess,64,Instant(deadline),current)}
fn setup(deadline:u64)->real_std::result::Result<Zeroizing<Vec<u8>>,ObservedFrameError>{read_setup_frame_capped_checked_observed_until(&UnixStream,&PeerProcess,64,Instant(deadline),current)}
fn cause<T:core::fmt::Debug>(result:real_std::result::Result<T,ObservedFrameError>,expected:FrameReadCause,error:Error){let got=result.unwrap_err();assert_eq!(got.cause,expected);assert_eq!(got.error,error);}
#[test]fn ordinary_long_budget_rejects_before_current_or_receive(){reset();cause(ordinary(120001),FrameReadCause::InvalidBudget,Error::InvalidData);assert_eq!(snapshot(),(vec![],0,1,1));}
#[test]fn setup_long_budget_enters_same_authenticated_transfer(){reset();assert_eq!(&**setup(900000).unwrap(),b"ok");assert_eq!(snapshot().1,3);assert_eq!(snapshot().0.iter().filter(|e|**e=="recv").count(),1);assert_eq!(snapshot().0.iter().filter(|e|**e=="poll").count(),1);let observed=snapshot();reset();assert_eq!(&**read_setup_frame_capped_checked_until(&UnixStream,&PeerProcess,64,Instant(900000),current).unwrap(),b"ok");assert_eq!(snapshot(),observed);}
#[test]fn exact_budget_boundaries_remain_closed(){for d in [120000,120001,900000,900001]{reset();let r=ordinary(d);if d<=120000{assert_eq!(&**r.unwrap(),b"ok")}else{cause(r,FrameReadCause::InvalidBudget,Error::InvalidData)}reset();let r=setup(d);if d<=900000{assert_eq!(&**r.unwrap(),b"ok")}else{cause(r,FrameReadCause::InvalidBudget,Error::InvalidData);assert!(snapshot().0.is_empty());}}}
#[test]fn zero_and_expired_deadlines_deny_without_io(){for is_setup in [false,true]{for now in [0,1]{reset();edit(|s|s.now=now);let r=if is_setup{setup(0)}else{ordinary(0)};cause(r,FrameReadCause::Deadline,Error::Authentication);assert!(snapshot().0.is_empty());}}}
#[test]fn invalid_byte_budgets_deny_before_any_poll_or_read(){for cap in [0,MAX_FRAME+1]{for is_setup in [false,true]{reset();let r=if is_setup{read_setup_frame_capped_checked_observed_until(&UnixStream,&PeerProcess,cap,Instant(900000),current)}else{read_frame_capped_checked_observed_until(&UnixStream,&PeerProcess,cap,Instant(120000),current)};cause(r,FrameReadCause::FrameLimit,Error::Limit);assert!(snapshot().0.is_empty());}}}
#[test]fn passive_wait_consumes_zero_bytes_until_readability(){reset();edit(|s|s.polls=vec![Poll::idle(100),Poll::idle(100),Poll::readable(100)].into());assert_eq!(&**setup(900000).unwrap(),b"ok");let t=snapshot().0;let first=t.iter().position(|v|*v=="recv").unwrap();assert_eq!(t[..first].iter().filter(|v|**v=="poll").count(),3);assert_eq!(t[..first].iter().filter(|v|**v=="recv").count(),0);assert_eq!(snapshot().1,3);}
#[test]fn passive_deadline_after_poll_denies_even_if_readable(){for ready in [false,true]{reset();edit(|s|s.polls=vec![if ready{Poll::readable(900000)}else{Poll::idle(900000)}].into());cause(setup(900000),FrameReadCause::Deadline,Error::Authentication);assert_eq!(snapshot().1,0);assert_eq!(snapshot().3,1);}}
#[test]fn setup_currentness_before_and_after_poll_preserves_error(){for n in [1,2]{reset();edit(|s|s.fail_current=Some(n));cause(setup(900000),FrameReadCause::CurrentCheck,Error::CurrentSentinel);assert_eq!(snapshot().1,0);assert_eq!(snapshot().3,1);assert_eq!(snapshot().0.iter().filter(|e|**e=="poll").count(),n-1);}}
#[test]fn setup_peer_before_and_after_poll_preserves_error(){for n in [1,2]{reset();edit(|s|s.fail_peer=Some(n));cause(setup(900000),FrameReadCause::PeerNotLive,Error::PeerSentinel);assert_eq!(snapshot().1,0);assert_eq!(snapshot().3,1);}}
#[test]fn mixed_readability_and_poll_denials_preserve_authentication(){reset();edit(|s|s.polls.front_mut().unwrap().flags=libc::POLLIN|libc::POLLHUP);cause(before::run(900000),FrameReadCause::Eof,Error::Authentication);assert_eq!(snapshot().1,0);assert_eq!(snapshot().3,1);reset();edit(|s|s.polls.front_mut().unwrap().flags=libc::POLLIN|libc::POLLHUP);assert_eq!(&**setup(900000).unwrap(),b"ok");assert_eq!(snapshot().1,3);reset();edit(|s|{s.polls.front_mut().unwrap().flags=libc::POLLIN|libc::POLLHUP;s.reads=vec![Read::bytes(0,b"o"),Read::bytes(0,b"")].into();});cause(setup(900000),FrameReadCause::Eof,Error::Authentication);assert_eq!(snapshot().1,1);for (flags,expected) in [(libc::POLLHUP,FrameReadCause::Eof),(libc::POLLERR,FrameReadCause::Io),(libc::POLLIN|libc::POLLERR,FrameReadCause::Io),(libc::POLLNVAL,FrameReadCause::Io),(libc::POLLIN|libc::POLLNVAL,FrameReadCause::Io),(0,FrameReadCause::InvalidFrame)]{reset();edit(|s|s.polls=vec![Poll{advance:1,ready:1,flags,error:std::io::ErrorKind::Other}].into());cause(setup(900000),expected,Error::Authentication);assert_eq!(snapshot().1,0);}reset();edit(|s|s.polls=vec![Poll{advance:1,ready:-1,flags:0,error:std::io::ErrorKind::Other}].into());cause(setup(900000),FrameReadCause::Io,Error::Io(std::io::Error(std::io::ErrorKind::Other)));}
#[test]fn interrupted_poll_does_not_reset_original_deadline(){reset();edit(|s|s.polls=vec![Poll{advance:899950,ready:-1,flags:0,error:std::io::ErrorKind::Interrupted},Poll::readable(50)].into());cause(setup(900000),FrameReadCause::Deadline,Error::Authentication);assert_eq!(snapshot().1,0);STATE.with(|s|assert_eq!(s.borrow().waits,vec![100,50]));}
#[test]fn first_readability_transfer_is_minimum_of_original_and_120s(){for (readable,transfer) in [(0,120000),(780000,900000),(850000,900000)]{reset();assert_eq!(setup_transfer_deadline(Instant(900000),Instant(readable)).unwrap(),Instant(transfer));edit(|s|{s.polls=vec![Poll::readable(readable)].into();s.reads=vec![Read::bytes(transfer-readable-1,b"ok\n")].into();});assert_eq!(&**setup(900000).unwrap(),b"ok");reset();edit(|s|{s.polls=vec![Poll::readable(readable)].into();s.reads=vec![Read::bytes(transfer-readable,b"ok\n")].into();});cause(setup(900000),FrameReadCause::Deadline,Error::Authentication);}}
#[test]fn partial_transfer_never_renews_and_never_reenters_setup(){reset();edit(|s|{s.reads=vec![Read::bytes(119000,b"o"),Read::bytes(1000,b"k\n"),Read::bytes(0,b"unused\n")].into();s.polls.push_back(Poll::readable(0));});cause(setup(900000),FrameReadCause::Deadline,Error::Authentication);let t=snapshot();assert_eq!(t.2,1);assert_eq!(t.3,1);assert_eq!(t.0.iter().filter(|e|**e=="poll").count(),1);assert_eq!(t.0.iter().filter(|e|**e=="recv").count(),2);}
#[test]fn timeout_and_eintr_preserve_partial_frame_and_original_ceiling(){for k in [std::io::ErrorKind::WouldBlock,std::io::ErrorKind::TimedOut,std::io::ErrorKind::Interrupted]{reset();edit(|s|s.reads=vec![Read::bytes(1,b"o"),Read::error(119999,k),Read::bytes(0,b"k\n")].into());cause(setup(900000),FrameReadCause::Deadline,Error::Authentication);assert_eq!(snapshot().3,1);assert_eq!(snapshot().1,1);reset();edit(|s|s.reads=vec![Read::bytes(1,b"o"),Read::error(1,k),Read::bytes(1,b"k\n")].into());assert_eq!(&**setup(900000).unwrap(),b"ok");}}
#[test]fn transfer_eof_and_timeout_setup_errors_are_not_retried(){reset();edit(|s|s.reads=vec![Read::bytes(0,b""),Read::bytes(0,b"unused\n")].into());cause(setup(900000),FrameReadCause::Eof,Error::Authentication);assert_eq!(snapshot().3,1);reset();edit(|s|s.timeout_error=true);cause(setup(900000),FrameReadCause::Io,Error::Io(std::io::Error(std::io::ErrorKind::Other)));assert_eq!(snapshot().1,0);assert_eq!(snapshot().3,1);}
#[test]fn actual_credential_ancillary_and_truncation_denials_remain(){for (ancillary,expected) in [(Ancillary::Missing,FrameReadCause::CredentialsMissing),(Ancillary::Wrong,FrameReadCause::CredentialsMismatch),(Ancillary::Duplicate,FrameReadCause::CredentialsMismatch),(Ancillary::Unexpected,FrameReadCause::AncillaryRejected),(Ancillary::Truncated,FrameReadCause::Truncated)]{for hup in [false,true]{reset();edit(|s|{s.reads.front_mut().unwrap().ancillary=ancillary;if hup{s.polls.front_mut().unwrap().flags=libc::POLLIN|libc::POLLHUP;}});cause(setup(900000),expected,Error::Authentication);if matches!(ancillary,Ancillary::Unexpected){assert!(snapshot().0.contains(&"close-inert-fd"));}}}}
#[test]fn unchanged_inner_byte_limit_and_delimiter_parser_reject(){for bytes in [b"abcde".as_slice(),b"abcde\n".as_slice(),b"a\nb".as_slice()]{reset();edit(|s|s.reads=vec![Read::bytes(0,bytes)].into());let r=read_setup_frame_capped_checked_observed_until(&UnixStream,&PeerProcess,5,Instant(900000),current);let e=r.unwrap_err();assert_eq!(e.cause,if bytes==b"a\nb"{FrameReadCause::InvalidFrame}else{FrameReadCause::FrameLimit});}reset();edit(|s|s.reads=vec![Read::bytes(0,b"abcd\n")].into());assert_eq!(&**read_setup_frame_capped_checked_observed_until(&UnixStream,&PeerProcess,5,Instant(900000),current).unwrap(),b"abcd");}
#[test]fn final_receive_source_and_peer_checks_can_reject_complete_bytes(){for hup in [false,true]{reset();edit(|s|{s.fail_current=Some(5);if hup{s.polls.front_mut().unwrap().flags=libc::POLLIN|libc::POLLHUP;}});cause(setup(900000),FrameReadCause::CurrentCheck,Error::CurrentSentinel);assert_eq!(snapshot().1,3);reset();edit(|s|{s.fail_peer=Some(3);if hup{s.polls.front_mut().unwrap().flags=libc::POLLIN|libc::POLLHUP;}});cause(setup(900000),FrameReadCause::PeerNotLive,Error::PeerSentinel);assert_eq!(snapshot().1,3);}}
#[test]fn restricted_setup_preserves_last_denial_before_recv(){for hup in [false,true]{reset();if hup{edit(|s|s.polls.front_mut().unwrap().flags=libc::POLLIN|libc::POLLHUP);}let mut calls=0;let r=read_setup_frame_capped_restricted_observed_until(&UnixStream,&PeerProcess,64,Instant(900000),current,||{calls+=1;Err(Error::CurrentSentinel)});cause(r,FrameReadCause::CurrentCheck,Error::CurrentSentinel);assert_eq!(calls,1);assert_eq!(snapshot().1,0);assert_eq!(snapshot().3,1);reset();if hup{edit(|s|s.polls.front_mut().unwrap().flags=libc::POLLIN|libc::POLLHUP);}let mut calls=0;let r=read_setup_frame_capped_restricted_observed_until(&UnixStream,&PeerProcess,64,Instant(900000),current,||{calls+=1;Ok(())});assert_eq!(&**r.unwrap(),b"ok");assert_eq!(calls,1);assert_eq!(snapshot().1,3);}}
#[test]fn ordinary_valid_transfer_remains_same_parser_without_passive_poll(){reset();assert_eq!(&**ordinary(120000).unwrap(),b"ok");assert!(!snapshot().0.contains(&"poll"));for (ancillary,expected) in [(Ancillary::Wrong,FrameReadCause::CredentialsMismatch),(Ancillary::Truncated,FrameReadCause::Truncated)]{reset();edit(|s|s.reads.front_mut().unwrap().ancillary=ancillary);cause(ordinary(120000),expected,Error::Authentication);assert!(!snapshot().0.contains(&"poll"));}}
'''

HELPER_PREFIX = r'''
mod readiness_helper {
 use super::{Instant,UnixStream,PeerProcess,FrameReadCause,Duration};
 use crate::real_std::{cell::RefCell,collections::HashMap};
 #[derive(Clone,Debug,PartialEq,Eq)]enum BridgeError{Permission,Ipc,Binding,Sentinel(&'static str)}
 type Result<T>=crate::real_std::result::Result<T,BridgeError>;
 #[derive(Debug,PartialEq,Eq)]struct CoordinatedClosedResponseV1;
 const MAX_METADATA_V3:usize=64;
 struct HelperScript{trace:Vec<&'static str>,counts:HashMap<&'static str,usize>,fail:Option<(&'static str,usize)>}
 thread_local!{static SCRIPT:RefCell<HelperScript>=RefCell::new(HelperScript{trace:vec![],counts:HashMap::new(),fail:None});}
 fn reset(fail:Option<(&'static str,usize)>){super::reset();SCRIPT.with(|s|*s.borrow_mut()=HelperScript{trace:vec![],counts:HashMap::new(),fail});}
 fn step(name:&'static str)->Result<()>{SCRIPT.with(|s|{let mut s=s.borrow_mut();s.trace.push(name);let count={let v=s.counts.entry(name).or_insert(0);*v+=1;*v};if s.fail==Some((name,count)){Err(BridgeError::Sentinel(name))}else{Ok(())}})}
 fn require_before(deadline:Instant)->Result<()>{step("deadline")?;if Instant::now()>=deadline{Err(BridgeError::Permission)}else{Ok(())}}
 struct CoordinatedOriginalClientV1{peer:PeerProcess,deadline:Instant}
 impl CoordinatedOriginalClientV1{fn check_stream(&self,_:&UnixStream)->Result<()>{step("stream")}}
 mod wholepact_signer_origin{
  pub(super) use crate::Error;
  pub(super) mod framing{pub(crate) use crate::{FrameReadCause,read_setup_frame_capped_checked_observed_until,read_frame_capped_checked_observed_until};}
 }
 mod wholepact_core{pub(super) mod strict_json{pub(crate) fn parse_typed_json_with_byte_limit(bytes:&[u8],cap:usize)->super::super::Result<super::super::CoordinatedClosedResponseV1>{super::super::step("parse")?;assert_eq!(bytes,b"ok");assert_eq!(cap,64);Ok(super::super::CoordinatedClosedResponseV1)}}}
'''
HELPER_TESTS = r'''
 fn run(deadline:u64,ordinary:bool)->(Result<CoordinatedClosedResponseV1>,CoordinatedAdmissionFailureStageV1,Option<FrameReadCause>){let c=CoordinatedOriginalClientV1{peer:PeerProcess,deadline:Instant(deadline)};let mut stage=CoordinatedAdmissionFailureStageV1::ResponseDecode;let mut frame=Some(FrameReadCause::Unclassified);let r=if ordinary{c.closed_response_detailed_v1(&UnixStream,Instant(deadline),&||step("check"),&mut stage,&mut frame)}else{c.preparation_readiness_response(&UnixStream,Instant(deadline),&||step("check"),&mut stage,&mut frame)};(r,stage,frame)}
 #[test]fn actual_helper_all_eight_error_stages_preserve_original_error(){use CoordinatedAdmissionFailureStageV1::*;for (failure,expected) in [(("check",1),ResponseCheckBefore),(("stream",1),ResponsePeerBefore),(("deadline",1),ResponseDeadlineBefore),(("check",7),ResponseCheckAfter),(("stream",7),ResponsePeerAfter),(("deadline",2),ResponseDeadlineAfter),(("parse",1),ResponseDecode)]{reset(Some(failure));let (r,s,f)=run(900000,false);assert_eq!(s,expected);assert_eq!(f,None);assert_eq!(r,Err(if failure.0=="parse"{BridgeError::Binding}else{BridgeError::Sentinel(failure.0)}));}reset(None);super::edit(|s|s.reads=vec![super::Read::bytes(0,b"")].into());let(r,s,f)=run(900000,false);assert_eq!(r,Err(BridgeError::Ipc));assert_eq!(s,ResponseFrame);assert_eq!(f,Some(FrameReadCause::Eof));}
 #[test]fn actual_helper_forwards_real_frame_budget_and_currentness_causes(){use CoordinatedAdmissionFailureStageV1::*;reset(None);let(r,s,f)=run(900001,false);assert_eq!((r,s,f),(Err(BridgeError::Ipc),ResponseFrame,Some(FrameReadCause::InvalidBudget)));assert!(super::snapshot().0.is_empty());for fail in [("check",2),("stream",2)]{reset(Some(fail));let(r,s,f)=run(900000,false);assert_eq!((r,s,f),(Err(BridgeError::Ipc),ResponseFrame,Some(FrameReadCause::CurrentCheck)));assert_eq!(super::snapshot().1,0);}reset(None);super::edit(|s|s.fail_peer=Some(1));let(r,s,f)=run(900000,false);assert_eq!((r,s,f),(Err(BridgeError::Ipc),ResponseFrame,Some(FrameReadCause::PeerNotLive)));}
 #[test]fn actual_helper_success_uses_setup_only_and_no_failure_observation(){reset(None);let(r,_,f)=run(900000,false);assert_eq!(r,Ok(CoordinatedClosedResponseV1));assert_eq!(f,None);SCRIPT.with(|s|{let s=s.borrow();assert_eq!(s.counts.get("check"),Some(&7));assert_eq!(s.counts.get("stream"),Some(&7));assert_eq!(s.counts.get("deadline"),Some(&2));assert_eq!(s.counts.get("parse"),Some(&1));});assert_eq!(super::snapshot().0.iter().filter(|e|**e=="recv").count(),1);reset(None);let(r,s,f)=run(900000,true);assert_eq!((r,s,f),(Err(BridgeError::Ipc),CoordinatedAdmissionFailureStageV1::ResponseFrame,Some(FrameReadCause::InvalidBudget)));assert_eq!(super::snapshot().1,0);reset(None);assert_eq!(run(120000,true).0,Ok(CoordinatedClosedResponseV1));}
}
'''

MAPPER_PREFIX = r'''
mod host_mapper {
 use super::readiness_helper::CoordinatedAdmissionFailureStageV1;
 use crate::real_std::cell::RefCell;
 #[derive(Debug,PartialEq,Eq)]pub enum BridgeError{Binding,Conflict,Missing,Uncertain,Limit,Permission,RecoveryRequired,CompleteOriginRecoveryUnavailable,Verification,SignerOriginUnavailable,Journal(String),Authority(String),Wallet(String),Ipc}
 mod wholepact_signer_origin{pub(super) mod framing{pub(crate) use crate::FrameReadCause;}}
 mod wholepact_signer{pub(super) mod authority_bridge{
  pub(crate) use super::super::BridgeError;
  pub(crate) mod durable_review_ipc_v3{pub(crate) mod coordinated_v1{
   pub(crate) use super::super::super::super::{CoordinatedPreparationFailureV1,CoordinatedAdmissionFailureStageV1};
  }}
 }}
 // Inert first-event sink only. Real actor PID-bound CAS is separately covered
 // by the maintained Host diagnostic witness, not simulated as an authority.
 thread_local!{static EVENTS:RefCell<Option<(Stage,Class)>>=RefCell::new(None);}
 fn latch_failure(stage:Stage,class:Class){EVENTS.with(|v|{let mut v=v.borrow_mut();if v.is_none(){*v=Some((stage,class));}})}
 fn take()->Option<(Stage,Class)>{EVENTS.with(|v|v.borrow_mut().take())}
'''
MAPPER_TESTS = r'''
 #[test]fn finite_mapper_preserves_stage_frame_absence_and_owned_error(){
  use CoordinatedAdmissionFailureStageV1 as S;use super::FrameReadCause as F;
  for (source,target) in [(S::ResponseCheckBefore,Stage::PreparationReadinessCheckBefore),(S::ResponsePeerBefore,Stage::PreparationReadinessPeerBefore),(S::ResponseDeadlineBefore,Stage::PreparationReadinessDeadlineBefore),(S::ResponseFrame,Stage::PreparationReadinessFrame),(S::ResponseCheckAfter,Stage::PreparationReadinessCheckAfter),(S::ResponsePeerAfter,Stage::PreparationReadinessPeerAfter),(S::ResponseDeadlineAfter,Stage::PreparationReadinessDeadlineAfter),(S::ResponseDecode,Stage::PreparationReadinessDecode)]{
   assert_eq!(take(),None);let e=CoordinatedPreparationFailureV1{readiness:Some((source,None)),error:BridgeError::Permission};preparation_readiness(&e);assert_eq!(take(),Some((target,Class::BridgePermission)));assert_eq!(e.into_error(),BridgeError::Permission);
  }
  for (source,target) in [(F::Unclassified,Class::FrameUnclassified),(F::Deadline,Class::FrameDeadline),(F::Eof,Class::FrameEof),(F::CredentialsMissing,Class::FrameCredentialsMissing),(F::CredentialsMismatch,Class::FrameCredentialsMismatch),(F::AncillaryRejected,Class::FrameAncillaryRejected),(F::Truncated,Class::FrameTruncated),(F::PeerNotLive,Class::FramePeerNotLive),(F::CurrentCheck,Class::FrameCurrentCheck),(F::Io,Class::FrameIo),(F::FrameLimit,Class::FrameLimit),(F::InvalidFrame,Class::FrameInvalidFrame),(F::InvalidBudget,Class::FrameInvalidBudget)]{
   let e=CoordinatedPreparationFailureV1{readiness:Some((S::ResponseFrame,Some(source))),error:BridgeError::Ipc};preparation_readiness(&e);assert_eq!(take(),Some((Stage::PreparationReadinessFrame,target)));assert_eq!(e.into_error(),BridgeError::Ipc);
  }
  for readiness in [None,Some((S::HistoryOpen,None))]{let e=CoordinatedPreparationFailureV1{readiness,error:BridgeError::Permission};preparation_readiness(&e);assert_eq!(take(),None);assert_eq!(e.into_error(),BridgeError::Permission);}
  let payload=String::from("public-synthetic-payload-not-an-observation");let pointer=payload.as_ptr();let e=CoordinatedPreparationFailureV1{readiness:Some((S::ResponseCheckBefore,None)),error:BridgeError::Journal(payload)};preparation_readiness(&e);assert_eq!(take(),Some((Stage::PreparationReadinessCheckBefore,Class::BridgeJournal)));match e.into_error(){BridgeError::Journal(p)=>assert_eq!(p.as_ptr(),pointer),_=>panic!("original error variant changed")}
  latch_failure(Stage::LaterWorkflow,Class::Permission);let e=CoordinatedPreparationFailureV1{readiness:Some((S::ResponseFrame,Some(F::InvalidBudget))),error:BridgeError::Ipc};preparation_readiness(&e);assert_eq!(take(),Some((Stage::LaterWorkflow,Class::Permission)));
 }
}
'''

EXPECTED = [
    'ordinary_long_budget_rejects_before_current_or_receive',
    'setup_long_budget_enters_same_authenticated_transfer',
    'exact_budget_boundaries_remain_closed',
    'zero_and_expired_deadlines_deny_without_io',
    'invalid_byte_budgets_deny_before_any_poll_or_read',
    'passive_wait_consumes_zero_bytes_until_readability',
    'passive_deadline_after_poll_denies_even_if_readable',
    'setup_currentness_before_and_after_poll_preserves_error',
    'setup_peer_before_and_after_poll_preserves_error',
    'mixed_readability_and_poll_denials_preserve_authentication',
    'interrupted_poll_does_not_reset_original_deadline',
    'first_readability_transfer_is_minimum_of_original_and_120s',
    'partial_transfer_never_renews_and_never_reenters_setup',
    'timeout_and_eintr_preserve_partial_frame_and_original_ceiling',
    'transfer_eof_and_timeout_setup_errors_are_not_retried',
    'actual_credential_ancillary_and_truncation_denials_remain',
    'unchanged_inner_byte_limit_and_delimiter_parser_reject',
    'final_receive_source_and_peer_checks_can_reject_complete_bytes',
    'restricted_setup_preserves_last_denial_before_recv',
    'ordinary_valid_transfer_remains_same_parser_without_passive_poll',
    'readiness_helper::actual_helper_all_eight_error_stages_preserve_original_error',
    'readiness_helper::actual_helper_forwards_real_frame_budget_and_currentness_causes',
    'readiness_helper::actual_helper_success_uses_setup_only_and_no_failure_observation',
    'host_mapper::finite_mapper_preserves_stage_frame_absence_and_owned_error',
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    root, out = args.source.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    path = 'crates/wholepact-signer-origin/src/framing.rs'
    raw = (root / path).read_bytes()
    source = raw.decode()
    # Normalize ONLY the reviewed mixed-HUP reorder back to exact P48. All
    # budget, currentness and inner receiver bytes remain unchanged.
    current_setup = block(source, 'fn read_setup_frame_capped_observed_kernel(')
    changed_error = """            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                cause = FrameReadCause::Io;
                return Err(Error::Authentication);
            }
            // A one-response stream may close after queueing its complete
            // frame. POLLIN|POLLHUP still has bytes to authenticate: enter the
            // unchanged parser before treating HUP alone as EOF. Its peer,
            // credentials, byte/deadline and final-restriction checks remain.
"""
    original_error = """            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0 {
                cause = if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    FrameReadCause::Io
                } else {
                    FrameReadCause::Eof
                };
                return Err(Error::Authentication);
            }
"""
    moved_hup = """            if descriptor.revents & libc::POLLHUP != 0 {
                cause = FrameReadCause::Eof;
                return Err(Error::Authentication);
            }
"""
    assert current_setup.count(changed_error) == 1 and current_setup.count(moved_hup) == 1
    old_setup = current_setup.replace(changed_error, original_error).replace(moved_hup, '')
    original_source = source.replace(current_setup, old_setup)
    assert hashlib.sha256(original_source.encode()).hexdigest() == 'f162b856e0d1052c833e2d4377d14ad4fb3d8d9b24990e410dfeee3e917bad87' 
    assert 'const MAX_FRAME: usize = 2_100_000;' in source
    client_path = 'crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/lifecycle_v1.rs'
    client_raw = (root / client_path).read_bytes()
    client = client_raw.decode()
    method = block(client, 'fn prepare_closed_recipient_inner_v1(')
    ordinary_wrapper = block(client, 'pub fn prepare_closed_recipient_v1(')
    observed_wrapper = block(client, 'pub fn prepare_closed_recipient_observed_v1(')
    assert ordinary_wrapper.count('self.prepare_closed_recipient_inner_v1(') == 1
    assert observed_wrapper.count('self.prepare_closed_recipient_inner_v1(') == 1
    assert 'self.prepare_closed_recipient_inner_v1(request, fixed, payload_digest, payload_bytes, delivery, material_scopes, &mut None)' in ordinary_wrapper
    assert '.map_err(|error| CoordinatedPreparationFailureV1 { readiness, error })' in observed_wrapper
    setup_helper = block(client, 'fn preparation_readiness_response(')
    normal_helper = block(client, 'pub(super) fn closed_response_detailed_v1(')
    changed = """            // The first response is inert readiness only. Its original channel
            // may exceed a single transfer's 120-second budget; wait without
            // consuming bytes, then enter the same authenticated frame parser.
            // Initial Prepare and the second, permission-bearing query keep
            // their unchanged ordinary short-response path.
            let response = if readiness.is_none() {
                let mut stage = CoordinatedAdmissionFailureStageV1::ResponseCheckBefore;
                let mut frame_cause = None;
                let result = self.preparation_readiness_response(&stream, deadline, &|| Ok(()), &mut stage, &mut frame_cause);
                if result.is_err() { *readiness_failure = Some((stage, frame_cause)); }
                result
            } else {
                self.closed_response(&stream, deadline, &|| Ok(()))
            }?;
            match response {"""
    assert method.count(changed) == 1
    prior = method.replace(changed, '            match self.closed_response(&stream, deadline, &|| Ok(()))? {')
    prior = prior.replace('fn prepare_closed_recipient_inner_v1(', 'pub fn prepare_closed_recipient_v1(').replace('        readiness_failure: &mut Option<(CoordinatedAdmissionFailureStageV1, Option<wholepact_signer_origin::framing::FrameReadCause>)>,\n', '')
    assert hashlib.sha256(prior.encode()).hexdigest() == '49cbd43a1f4a425545dba6fa642d8ff19e599d28ea466559161396901226e4db'
    assert method.count('self.preparation_readiness_response(') == 1
    assert client.count('self.preparation_readiness_response(') == 1
    assert method.count('self.closed_response(&stream, deadline, &|| Ok(()))') == 2
    # The helper is the same current/peer/deadline/frame/decode kernel except
    # the single selected frame function. Whitespace-only differences allowed.
    ordinary_body = normal_helper[normal_helper.index('{'):]
    setup_body = setup_helper[setup_helper.index('{'):]
    ordinary_body = ordinary_body.replace('read_frame_capped_checked_observed_until(', 'read_setup_frame_capped_checked_observed_until(')
    assert re.sub(r'\s+', '', ordinary_body) == re.sub(r'\s+', '', setup_body)
    admission_path = 'crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/admission_v1.rs'
    admission_raw = (root / admission_path).read_bytes()
    stage_enum = block(admission_raw.decode(), 'pub enum CoordinatedAdmissionFailureStageV1 {')
    failure_struct = block(client, 'pub struct CoordinatedPreparationFailureV1 {')
    failure_impl = block(client, 'impl CoordinatedPreparationFailureV1 {')
    host_path = 'crates/wholepact-native-host/src/financial_ci_host_failure.rs'
    host_raw = (root / host_path).read_bytes()
    mapper = block(host_raw.decode(), 'pub(crate) fn preparation_readiness(')
    bridge = block(host_raw.decode(), 'pub(crate) fn bridge(')
    codes_path = 'crates/wholepact-financial-coordinator-origin/src/financial_ci_host_diagnostics.rs'
    codes_raw = (root / codes_path).read_bytes()
    codes = codes_raw.decode()
    code_macro = block(codes, 'macro_rules! codes {')
    host_codes = [block(codes, 'codes!('+name+' {')+');' for name in ['Stage','Class']]
    markers = [
        'pub enum FrameReadCause {', 'pub struct ObservedFrameError {', 'fn observe<T>(',
        'pub fn read_setup_frame_capped_checked_until(',
        'pub fn read_setup_frame_capped_checked_observed_until(',
        'pub fn read_setup_frame_capped_restricted_observed_until(',
        'fn read_setup_frame_capped_observed_kernel(', 'fn setup_transfer_deadline(',
        'pub fn read_frame_capped_checked_observed_until(',
        'fn read_frame_capped_observed_kernel(', 'fn admit_restricted_receive(',
        'fn remaining_at(', 'fn append_capped_chunk(', 'fn read_frame_inner_observed(',
    ]
    fragments = [(marker, block(source, marker)) for marker in markers]
    text = PREFIX + '\n'
    for marker, fragment in fragments:
        if marker == 'pub enum FrameReadCause {':
            text += '#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'
        elif marker == 'pub struct ObservedFrameError {':
            text += '#[derive(Debug)]\n'
        text += fragment + '\n'
    text += '\nmod before { use super::*;\n' + old_setup + '\npub(super) fn run(deadline:u64)->std::result::Result<Zeroizing<Vec<u8>>,ObservedFrameError>{read_setup_frame_capped_observed_kernel(&UnixStream,&PeerProcess,64,Instant(deadline),current,None)}\n}\n'
    text += TESTS
    text += HELPER_PREFIX + '#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n' + stage_enum + '\nimpl CoordinatedOriginalClientV1 {\n' + setup_helper + '\n' + normal_helper + '\n}\n' + HELPER_TESTS
    text += MAPPER_PREFIX + code_macro + '\n' + '\n'.join(host_codes) + '\n' + failure_struct + '\n' + failure_impl + '\n' + mapper + '\n' + bridge + '\n' + MAPPER_TESTS
    assert len(EXPECTED) == 24
    assert sorted(re.findall(r'#\[test\]fn (\w+)\(', text)) == sorted(name.split('::')[-1] for name in EXPECTED)
    generated = out / 'readiness-frame-trace.rs'
    generated.write_text(text)
    binding = {
        'version': 1, 'source': {'path': path, 'sha256': hashlib.sha256(raw).hexdigest()},
        'P48_normalized_framing_sha256': hashlib.sha256(original_source.encode()).hexdigest(),
        'P48_setup_kernel_sha256': hashlib.sha256(old_setup.encode()).hexdigest(),
        'client_source': {'path': client_path, 'sha256': hashlib.sha256(client_raw).hexdigest()},
        'admission_stage_source': {'path': admission_path, 'sha256': hashlib.sha256(admission_raw).hexdigest()},
        'stage_enum_sha256': hashlib.sha256(stage_enum.encode()).hexdigest(),
        'host_mapper_source': {'path': host_path, 'sha256': hashlib.sha256(host_raw).hexdigest()},
        'host_codes_source': {'path': codes_path, 'sha256': hashlib.sha256(codes_raw).hexdigest()},
        'host_mapper_sha256': hashlib.sha256(mapper.encode()).hexdigest(),
        'bridge_mapper_sha256': hashlib.sha256(bridge.encode()).hexdigest(),
        'failure_struct_sha256': hashlib.sha256(failure_struct.encode()).hexdigest(),
        'failure_impl_sha256': hashlib.sha256(failure_impl.encode()).hexdigest(),
        'host_macro_sha256': hashlib.sha256(code_macro.encode()).hexdigest(),
        'host_codes_sha256': [hashlib.sha256(v.encode()).hexdigest() for v in host_codes],
        'ordinary_wrapper_sha256': hashlib.sha256(ordinary_wrapper.encode()).hexdigest(),
        'observed_wrapper_sha256': hashlib.sha256(observed_wrapper.encode()).hexdigest(),
        'client_prepare_sha256': hashlib.sha256(method.encode()).hexdigest(),
        'P48_prepare_normalized_sha256': hashlib.sha256(prior.encode()).hexdigest(),
        'client_setup_helper_sha256': hashlib.sha256(setup_helper.encode()).hexdigest(),
        'client_normal_helper_sha256': hashlib.sha256(normal_helper.encode()).hexdigest(),
        'client_selector_and_operation_order_assertions': True,
        'fragments': [{'marker': marker, 'sha256': hashlib.sha256(body.encode()).hexdigest()} for marker, body in fragments],
        'generated_sha256': hashlib.sha256(text.encode()).hexdigest(),
        'expected_tests': EXPECTED, 'expected_count': len(EXPECTED), 'executed': False,
        'limitations': [
            'Clock, stream, poll/recvmsg, peer and ancillary carrier are inert scripted adapters.',
            'Actual setup/regular budget kernels, complete inner receiver/parser and currentness checks are literal source.',
            'Synthetic ancillary identities are not evidence of kernel credentials or real process custody.',
            'Mixed POLLIN|POLLHUP is explicitly injected: normalized P48 rejects before recv; new source reaches the same authenticated parser. Actual OS occurrence is not established.',
            'No actual socket, authority, native runtime or end-to-end execution is performed by this witness.',
            'Synthetic time jumps may model a scheduling delay longer than the requested bounded poll timeout.',
            'First/second client selector is source asserted; the full preparation DTO client is not executed here.',
            'Actual readiness helper invokes actual framing kernels; outer check_stream/require_before and JSON parse are scripted outcomes.',
            'Actual finite Host mapper and owned error accessors use inert error payloads and a first-event sink, not actor PID custody or observer IO.',
        ],
    }
    record = out / 'readiness-frame-source-bindings.json'
    record.write_text(json.dumps(binding, indent=2) + '\n')
    if args.run:
        binary = out / 'readiness-frame-trace'
        commands = [
            ([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', str(generated), '-o', str(binary)], 60, 'compile.log'),
            ([str(binary), '--list'], 10, 'list.log'),
            ([str(binary), '--test-threads=1'], 30, 'tests.log'),
        ]
        for command, timeout, log in commands:
            result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
            (out / log).write_text(result.stdout + result.stderr)
            if result.returncode:
                # Only this source-extracted test/compiler output is surfaced;
                # no product actor, fixture secret or private runtime is run.
                # Retain the full local log, but bound the workflow diagnostic.
                diagnostic = (result.stdout + result.stderr)[-16_384:]
                print(f'{log} diagnostic (last 16384 characters):', file=sys.stderr)
                print(diagnostic, file=sys.stderr)
                raise SystemExit(f'{log} failed: {result.returncode}')
            if log == 'list.log':
                names = re.findall(r'^(\w+(?:::\w+)*): test$', result.stdout, re.M)
                assert sorted(names) == sorted(EXPECTED), names
            if log == 'tests.log':
                assert f'test result: ok. {len(EXPECTED)} passed; 0 failed;' in result.stdout
        binding['executed'] = True
        record.write_text(json.dumps(binding, indent=2) + '\n')
    print(json.dumps({'generated': str(generated), 'tests': len(EXPECTED), 'executed': args.run}))


if __name__ == '__main__':
    main()
