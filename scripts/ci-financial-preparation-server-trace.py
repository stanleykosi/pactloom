#!/usr/bin/env python3
"""Extract the actual preparation-status server code into pure, inert Rust tests.

No sockets, actor authorities, clock leases, or product execution are created.
The transport sink, source/action/peer carriers and clock are explicit adapters.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


def block(text, marker, *, body_only=False):
    start = text.index(marker)
    opening = text.index('{', start)
    depth, position = 1, opening + 1
    # The extracted native functions contain no raw strings. Skip comments and
    # ordinary quoted strings rather than counting braces inside their text.
    token = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]', re.S)
    while depth:
        match = token.search(text, position)
        if match is None:
            raise ValueError('unclosed source block: ' + marker)
        value = match.group()
        if value == '{':
            depth += 1
        elif value == '}':
            depth -= 1
        position = match.end()
    return text[opening + 1:position - 1] if body_only else text[start:position]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--run', action='store_true', help='compile with $RUSTC or rustc, assert the exact 13-test listing, then execute')
    args = parser.parse_args()
    root, out = args.source.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    files, chunks = [], []

    def read(relative):
        data = (root / relative).read_bytes()
        files.append({'path': relative, 'sha256': hashlib.sha256(data).hexdigest()})
        return data.decode()

    def extract(source, marker, label, *, line_base=0, **kwargs):
        value = block(source, marker, **kwargs)
        chunks.append({'label': label, 'sha256': hashlib.sha256(value.encode()).hexdigest(),
                       'source_line': line_base + source[:source.index(marker)].count('\n') + 1})
        return value

    ipc = read('crates/wholepact-signer/src/ipc/coordinated_pair_v1.rs')
    delivery = read('crates/wholepact-signer/src/native_ui/runtime/coordinated_v3_delivery_v1.rs')
    driver = read('crates/wholepact-signer/src/native_ui/runtime/coordinated_financial_driver_v1.rs')
    lifecycle = read('crates/wholepact-signer/src/authority_bridge/durable_review_ipc_v3/coordinated_v1/lifecycle_v1.rs')
    deadline = extract(ipc, 'fn request_transport_deadline(', 'request_transport_deadline')
    closed_enum = extract(lifecycle, 'pub enum CoordinatedClosedCommandV1 {', 'closed DTO enum')
    # These DTO variants are used only as inert discriminants by the helper.
    assert re.findall(r'^    (\w+) \{', closed_enum, re.M) == [
        'Admit', 'AdmissionStatus', 'History', 'PreparationStatus', 'Activate', 'VerifyImport']
    request_enum = extract(ipc, 'pub(crate) enum CoordinatedRequestV1 {', 'request DTO enum binding')
    assert re.findall(r'^    (\w+)\(', request_enum, re.M) == [
        'FinancialResult', 'Closed', 'Redisclosure', 'Prepare']
    remaining = extract(delivery, 'fn remaining(deadline: Instant)', 'remaining')
    ready_impl = block(delivery, 'impl CoordinatedReadyToReceiveV1 {')
    ready_line_base = delivery[:delivery.index('impl CoordinatedReadyToReceiveV1 {')].count('\n')
    methods = [extract(ready_impl, marker, label, line_base=ready_line_base) for marker, label in [
        ('pub(super) fn check_current(', 'ready.check_current'),
        ('pub(super) fn preparation_digest(', 'ready.preparation_digest'),
        ('pub(super) fn respond_prepared(', 'ready.respond_prepared'),
        ('fn write_response(', 'ready.write_response')]]
    status_marker = 'CoordinatedClosedCommandV1::PreparationStatus {\n                        request_digest,\n                        nonce,\n                    } =>'
    # The first block in this marker is the pattern, not its body.
    status_start = driver.index(status_marker) + len(status_marker)
    status_body = block(driver[status_start:], '{', body_only=True)
    chunks.append({'label': 'Driver PreparationStatus arm body',
                   'sha256': hashlib.sha256(status_body.encode()).hexdigest(),
                   'source_line': driver[:status_start].count('\n') + 1})
    # Source-bound construction gate: do not invent or run a genuine Final.
    # As above, explicitly select the match-arm body after its pattern.
    receive_start = driver.index('Request::V3Receive { final_action } =>') + len('Request::V3Receive { final_action } =>')
    receive_body = block(driver[receive_start:], '{', body_only=True)
    chunks.append({'label': 'Driver V3Receive construction gate body',
                   'sha256': hashlib.sha256(receive_body.encode()).hexdigest(),
                   'source_line': driver[:receive_start].count('\n') + 1})
    assert 'State::DeliveryReceiveReview(review)' in receive_body
    assert 'self.state = State::DeliveryReady(review.consume_final(final_action)?);' in receive_body
    consume = extract(delivery, 'pub(super) fn consume_final(\n        self,\n        action: SignerV3ReceiveFinalV1,', 'receive.consume_final binding')
    for fragment in ['self.check_current()?;', 'action.check_current()?;',
                     'action.facts() != &self.facts || action.original_receive_deadline() != self.deadline',
                     'Ok(CoordinatedReadyToReceiveV1 {', '            action,']:
        assert fragment in consume
    assert 'let received_request_deadline = Instant::now() + Duration::from_secs(120);' in ipc
    assert re.search(r'original_request_deadline:\s*request_transport_deadline\(\s*&request,\s*received_request_deadline,\s*bounds\.deadline,\s*peer\.deadline\(\),?\s*\)', ipc)
    assert 'received_request_deadline.min(peer.deadline())' in ipc

    prelude = r'''#![allow(dead_code, unused_imports)]
// EXACT native methods below; all carriers, clock and sink in this prelude are inert.
use std::{cell::{Cell, RefCell}, rc::Rc, time::Duration};
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)] struct Instant(u64);
thread_local! {static NOW:Cell<u64>=const{Cell::new(1_000)}; static WRITES:RefCell<Vec<(Instant,CoordinatedClosedResponseV1)>>=const{RefCell::new(Vec::new())};}
impl Instant {fn now()->Self{Self(NOW.with(Cell::get))} fn saturating_duration_since(self,other:Self)->Duration{Duration::from_millis(self.0.saturating_sub(other.0))}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum Error {Locked,Authentication,ReviewMismatch,Uncertain,SourceSentinel,ActionSentinel}
type Result<T>=std::result::Result<T,Error>;
#[derive(Clone,Debug,PartialEq,Eq)]struct Intent(&'static str);
#[derive(Clone,Debug,PartialEq,Eq)]enum CoordinatedClosedResponseV1 {Prepared{nonce:String,intent:Intent,remaining_read_ms:u64,remaining_material_ms:u64}}
#[derive(Default)]struct Flags {source_calls:Cell<u32>,action_calls:Cell<u32>,source_fail_at:Cell<u32>,action_fail_at:Cell<u32>,peer_failure:Cell<bool>}
#[derive(Clone)]struct Peer {grant:u32,flags:Rc<Flags>}
impl Peer {fn require_same_grant(&self,other:&Self)->Result<()>{if self.grant==other.grant {Ok(())}else{Err(Error::Authentication)}} fn check_current(&self)->Result<()>{if self.flags.peer_failure.get(){Err(Error::Authentication)}else{Ok(())}}}
struct Source {flags:Rc<Flags>,peer:Peer,material:Instant}
impl Source {fn check_current(&self)->Result<()>{let n=self.flags.source_calls.get()+1;self.flags.source_calls.set(n);if self.flags.source_fail_at.get()==n{Err(Error::SourceSentinel)}else{Ok(())}} fn peer(&self)->&Peer{&self.peer} fn original_material_deadline(&self)->Instant{self.material}}
struct Action {flags:Rc<Flags>,deadline:Instant}
impl Action {fn check_current(&self)->Result<()>{let n=self.flags.action_calls.get()+1;self.flags.action_calls.set(n);if self.flags.action_fail_at.get()==n{Err(Error::ActionSentinel)}else{Ok(())}} fn original_receive_deadline(&self)->Instant{self.deadline}}
struct Prepared {preparation_digest:String}
struct CoordinatedReadyToReceiveV1 {source:Source,action:Action,intent:Intent,prepared:Prepared}
struct UnixStream; // Inert sink token, NOT std::os::unix::net::UnixStream.
mod ipc {pub(crate) type CoordinatedPairPeerV1=super::Peer;}
mod authority_bridge {
 #[derive(Debug)]pub enum BridgeError{Permission}
 pub mod durable_review_ipc_v3 {pub mod coordinated_v1 {
'''
    middle = r'''
 }}
 pub mod durable_review_ipc_v1 {
  use super::BridgeError; use crate::{CoordinatedClosedResponseV1,Instant,UnixStream,WRITES};
  // Explicit inert bounded-writer adapter. It exercises the native callbacks
  // and records their supplied ceiling; it makes no kernel/framing claims.
  pub(crate) fn bounded_write_restricted<F,P>(_:&mut UnixStream,response:&CoordinatedClosedResponseV1,deadline:Instant,mut current:F,peer:&P)->std::result::Result<(),BridgeError>
  where F:FnMut()->std::result::Result<(),BridgeError>,P:Fn()->std::result::Result<(),BridgeError> {
   current()?;peer()?;if Instant::now()>=deadline{return Err(BridgeError::Permission)}
   WRITES.with(|w|w.borrow_mut().push((deadline,response.clone())));Ok(())
  }
 }
}
use authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedClosedCommandV1;
enum CoordinatedRequestV1 {FinancialResult(()),Closed(CoordinatedClosedCommandV1),Redisclosure(Box<()>),Prepare(Box<()>)}
enum State {AwaitingOwner,DeliveryReadReview,DeliveryReceiveReview,DeliveryWorking,Redisclosed,DeliveryReady(CoordinatedReadyToReceiveV1),Taken}
enum DeliveryOutcome {Ready(CoordinatedReadyToReceiveV1)}
struct Driver {state:State,spawns:usize}
impl Driver {
 fn spawn_delivery(&mut self,work:impl FnOnce()->Result<DeliveryOutcome>)->Result<()> {self.spawns+=1;let DeliveryOutcome::Ready(ready)=work()?;self.state=State::DeliveryReady(ready);Ok(())}
 fn dispatch(&mut self,request_digest:String,nonce:String,peer:Peer,stream:UnixStream,original_request_deadline:Instant)->Result<()> {
'''
    tail = r'''
 Ok(())
 }
}
fn reset(){NOW.with(|n|n.set(1_000));WRITES.with(|w|w.borrow_mut().clear());}
fn writes()->Vec<(Instant,CoordinatedClosedResponseV1)>{WRITES.with(|w|w.borrow().clone())}
fn fixture(action:u64,material:u64)->(CoordinatedReadyToReceiveV1,Peer,Rc<Flags>){
 let flags=Rc::new(Flags::default());let peer=Peer{grant:7,flags:flags.clone()};
 let ready=CoordinatedReadyToReceiveV1{source:Source{flags:flags.clone(),peer:peer.clone(),material:Instant(material)},action:Action{flags:flags.clone(),deadline:Instant(action)},intent:Intent("inert-final-bound-intent"),prepared:Prepared{preparation_digest:"exact-staged-digest".into()}};(ready,peer,flags)
}
fn status()->CoordinatedRequestV1{CoordinatedRequestV1::Closed(CoordinatedClosedCommandV1::PreparationStatus{request_digest:"digest".into(),nonce:"nonce".into()})}
#[test]fn only_preparation_status_uses_original_parent_minimum(){
 reset();assert_eq!(request_transport_deadline(&status(),Instant(121_000),Instant(901_000),Instant(601_000)),Instant(601_000));
 assert_eq!(request_transport_deadline(&status(),Instant(121_000),Instant(61_000),Instant(601_000)),Instant(61_000));
}
#[test]fn every_other_request_variant_retains_original_120_second_cap(){
 use CoordinatedClosedCommandV1 as C;reset();
 let mut cases=vec![CoordinatedRequestV1::FinancialResult(()),CoordinatedRequestV1::Redisclosure(Box::new(())),CoordinatedRequestV1::Prepare(Box::new(()))];
 for c in [C::Admit{intent_digest:"d".into(),nonce:"n".into()},C::AdmissionStatus{intent_digest:"d".into(),nonce:"n".into()},C::History{intent_digest:"d".into(),authorization_id:"a".into(),nonce:"n".into()},C::Activate{intent_digest:"d".into(),nonce:"n".into()},C::VerifyImport{intent_digest:"d".into(),nonce:"n".into()}]{cases.push(CoordinatedRequestV1::Closed(c));}
 assert_eq!(cases.len(),8);for c in cases {assert_eq!(request_transport_deadline(&c,Instant(121_000),Instant(901_000),Instant(601_000)),Instant(121_000));assert_eq!(request_transport_deadline(&c,Instant(121_000),Instant(60_000),Instant(601_000)),Instant(60_000));}
}
#[test]fn expired_original_parent_is_not_renewed(){reset();assert_eq!(request_transport_deadline(&status(),Instant(121_000),Instant(999),Instant(601_000)),Instant(999));}
#[test]fn actual_driver_arm_rejects_all_pre_final_states_without_response(){
 reset();for state in [State::AwaitingOwner,State::DeliveryReadReview,State::DeliveryReceiveReview,State::DeliveryWorking,State::Redisclosed] {let(_,peer,_)=fixture(10_000,20_000);let mut d=Driver{state,spawns:0};assert_eq!(d.dispatch("exact-staged-digest".into(),"nonce".into(),peer,UnixStream,Instant(90_000)),Err(Error::ReviewMismatch));assert_eq!(d.spawns,0);}assert!(writes().is_empty());
}
#[test]fn actual_driver_arm_rejects_wrong_staged_digest(){reset();let(ready,peer,_)=fixture(10_000,20_000);let mut d=Driver{state:State::DeliveryReady(ready),spawns:0};assert_eq!(d.dispatch("wrong".into(),"nonce".into(),peer,UnixStream,Instant(90_000)),Err(Error::ReviewMismatch));assert_eq!(d.spawns,0);assert!(writes().is_empty());}
#[test]fn actual_driver_arm_emits_only_existing_ready_intent(){
 reset();let(ready,peer,_)=fixture(10_000,20_000);let mut d=Driver{state:State::DeliveryReady(ready),spawns:0};assert_eq!(d.dispatch("exact-staged-digest".into(),"first-nonce".into(),peer,UnixStream,Instant(90_000)),Ok(()));assert_eq!(d.spawns,1);
 let State::DeliveryReady(ready)=d.state else{panic!("ready lost")};assert_eq!(ready.action.deadline,Instant(10_000));assert_eq!(ready.source.material,Instant(20_000));assert_eq!(writes(),vec![(Instant(10_000),CoordinatedClosedResponseV1::Prepared{nonce:"first-nonce".into(),intent:Intent("inert-final-bound-intent"),remaining_read_ms:9_000,remaining_material_ms:19_000})]);
}
#[test]fn same_grant_is_required_before_response(){reset();let(ready,mut peer,_)=fixture(10_000,20_000);peer.grant=8;assert!(matches!(ready.respond_prepared(peer,UnixStream,"n".into(),Instant(90_000)),Err(Error::Authentication)));assert!(writes().is_empty());}
#[test]fn initial_source_and_action_errors_preserve_original_identity(){
 for source in [true,false]{reset();let(ready,peer,flags)=fixture(10_000,20_000);let error=if source{flags.source_fail_at.set(1);Error::SourceSentinel}else{flags.action_fail_at.set(1);Error::ActionSentinel};assert!(matches!(ready.respond_prepared(peer,UnixStream,"n".into(),Instant(90_000)),Err(e) if e==error));assert!(writes().is_empty());}
}
#[test]fn native_write_callback_rechecks_source_and_action(){
 for source in [true,false]{reset();let(ready,peer,flags)=fixture(10_000,20_000);if source{flags.source_fail_at.set(2)}else{flags.action_fail_at.set(2)}assert!(matches!(ready.respond_prepared(peer,UnixStream,"n".into(),Instant(90_000)),Err(Error::Uncertain)));assert!(writes().is_empty());}
}
#[test]fn native_write_callback_rechecks_peer_and_action(){
 for peer_failure in [true,false]{reset();let(ready,peer,flags)=fixture(10_000,20_000);if peer_failure{flags.peer_failure.set(true)}else{flags.action_fail_at.set(3)}assert!(matches!(ready.respond_prepared(peer,UnixStream,"n".into(),Instant(90_000)),Err(Error::Uncertain)));assert!(writes().is_empty());}
}
#[test]fn expired_action_material_or_request_never_writes(){
 for(action,material,request,error)in [(1_000,20_000,90_000,Error::Locked),(10_000,1_000,90_000,Error::Locked),(10_000,20_000,1_000,Error::Uncertain)]{reset();let(ready,peer,_)=fixture(action,material);assert!(matches!(ready.respond_prepared(peer,UnixStream,"n".into(),Instant(request)),Err(e) if e==error));assert!(writes().is_empty());}
}
#[test]fn actual_write_uses_all_three_original_deadlines_without_renewal(){
 for(action,material,request,expected)in [(10_000,20_000,30_000,10_000),(30_000,10_000,20_000,10_000),(30_000,20_000,10_000,10_000)] {reset();let(ready,peer,_)=fixture(action,material);let ready=ready.respond_prepared(peer.clone(),UnixStream,"first".into(),Instant(request)).unwrap_or_else(|_|panic!("first response"));NOW.with(|n|n.set(2_000));let ready=ready.respond_prepared(peer,UnixStream,"second".into(),Instant(request)).unwrap_or_else(|_|panic!("second response"));assert_eq!(ready.action.deadline,Instant(action));assert_eq!(ready.source.material,Instant(material));let w=writes();assert_eq!(w.len(),2);assert_eq!(w[0].0,Instant(expected));assert_eq!(w[1].0,Instant(expected));let CoordinatedClosedResponseV1::Prepared{remaining_read_ms:r0,remaining_material_ms:m0,..}=&w[0].1;let CoordinatedClosedResponseV1::Prepared{remaining_read_ms:r1,remaining_material_ms:m1,..}=&w[1].1;assert_eq!(*r0-*r1,1_000);assert_eq!(*m0-*m1,1_000);}
}
#[test]fn native_remaining_output_caps_do_not_replace_actual_write_ceiling(){reset();let(ready,peer,_)=fixture(501_000,1_801_000);assert!(ready.respond_prepared(peer,UnixStream,"n".into(),Instant(2_000_000)).is_ok());let w=writes();assert_eq!(w[0].0,Instant(501_000));let CoordinatedClosedResponseV1::Prepared{remaining_read_ms,remaining_material_ms,..}=&w[0].1;assert_eq!((*remaining_read_ms,*remaining_material_ms),(120_000,900_000));}
'''
    harness = prelude + closed_enum + middle + status_body + tail
    # Literal methods are placed in a child module so their native pub(super)
    # visibility remains unchanged; the implementations target inert carriers.
    harness += '\n' + deadline + '\n' + remaining + '\nmod actual_ready {use super::*;\nimpl CoordinatedReadyToReceiveV1 {\n' + '\n'.join(methods) + '\n}\n}\n'
    output = out / 'preparation-server-trace.rs'
    output.write_text(harness)
    test_count = len(re.findall(r'#\[test\]', harness))
    assert test_count == 13
    binding = {'version': 1, 'source_files': files, 'literal_chunks': chunks,
               'harness': {'name': output.name, 'sha256': hashlib.sha256(harness.encode()).hexdigest(), 'test_count': test_count},
               'execution': 'Generated only. Compile/run separately under pinned Rust.',
               'limits': ['Clock, source/action/peer, DTO payloads, Driver worker and bounded writer are inert adapters.',
                          'Driver PreparationStatus arm and Ready methods are literal; genuine Final construction is source-bound, not executed.',
                          'No socket, credentials, real actor authority, framing, runtime scheduling, hosted performance or full workflow claim.']}
    (out / 'preparation-server-source-bindings.json').write_text(json.dumps(binding, indent=2) + '\n')
    (out / 'run-preparation-server-trace.sh').write_text('#!/bin/sh\nset -eu\ncd "$(dirname "$0")"\nrustc --edition=2021 --test preparation-server-trace.rs -o preparation-server-trace-tests\n./preparation-server-trace-tests --test-threads=1\n')
    if args.run:
        executable = out / 'preparation-server-trace-tests'
        def run_logged(command, filename, timeout):
            completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
            (out / filename).write_text(completed.stdout)
            if completed.returncode != 0:
                print(completed.stdout, end='')
                raise SystemExit(completed.returncode)
            return completed.stdout
        run_logged([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', str(output), '-o', str(executable)], 'preparation-server-compile.log', 60)
        listing = run_logged([str(executable), '--list'], 'preparation-server-list.log', 10)
        listed = [line[:-len(': test')] for line in listing.splitlines() if line.endswith(': test')]
        expected = re.findall(r'#\[test\]\s*fn (\w+)\(', harness)
        if len(listed) != 13 or set(listed) != set(expected):
            raise SystemExit('compiled preparation-server test listing differs from the exact 13 expected names')
        result = run_logged([str(executable), '--test-threads=1'], 'preparation-server-tests.log', 30)
        print(result, end='')
        binding['execution'] = 'Compiled with selected RUSTC; exact 13-name test listing asserted; all executed tests passed.'
        (out / 'preparation-server-source-bindings.json').write_text(json.dumps(binding, indent=2) + '\n')
    print(json.dumps({'generated': output.name, 'tests': test_count, 'source_files': len(files), 'executed': args.run}))


if __name__ == '__main__':
    main()
