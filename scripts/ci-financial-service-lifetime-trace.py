#!/usr/bin/env python3
"""Actual passive fixture accepting loops and lifetime kernel; inert time/TCP/TLS.

No product authority, sockets, private fixture or native execution is fabricated.
The maintained constructor/check tests are also compiled literally here.
"""
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

PREFIX = r'''
extern crate std as real_std;
use real_std::{sync::{Arc,Mutex,TryLockError,atomic::{AtomicBool,Ordering}},time::Duration,cell::Cell};
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct Instant(u64);
impl Instant {fn now()->Self{CLOCK.with(|v|Self(v.get()))}fn checked_add(self,d:Duration)->Option<Self>{self.0.checked_add(d.as_nanos() as u64).map(Self)}fn checked_duration_since(self,other:Self)->Option<Duration>{self.0.checked_sub(other.0).map(Duration::from_nanos)}}
impl real_std::ops::Add<Duration> for Instant{type Output=Self;fn add(self,d:Duration)->Self{self.checked_add(d).unwrap()}}
impl real_std::ops::Sub<Duration> for Instant{type Output=Self;fn sub(self,d:Duration)->Self{Self(self.0-d.as_nanos() as u64)}}
thread_local!{static CLOCK:Cell<u64>=const{Cell::new(1_000_000_000)};static WALL:Cell<Option<u64>>=const{Cell::new(None)};static ACCEPTS:Cell<u32>=const{Cell::new(0)};static SERVES:Cell<u32>=const{Cell::new(0)};}
fn now_ms()->Result<u64>{Ok(WALL.with(|v|v.get()).unwrap_or(1000+Instant::now().0/1_000_000))}
#[derive(Debug,PartialEq,Eq)]enum AuthorityError{Expired,Permission}
type Result<T>=real_std::result::Result<T,AuthorityError>;
mod std{pub use crate::real_std::*;pub mod thread{pub fn sleep(d:crate::Duration){crate::CLOCK.with(|v|v.set(v.get()+d.as_nanos() as u64));}}}
struct Listener{fault:bool,revoke:Option<Arc<AtomicBool>>}
impl Listener{fn accept(&self)->real_std::io::Result<((),())>{ACCEPTS.with(|v|v.set(v.get()+1));if let Some(v)=&self.revoke{v.store(true,Ordering::Release);}if self.fault{Err(real_std::io::ErrorKind::ConnectionAborted.into())}else{Ok(((),()))}}}
struct Server{stopped:Arc<AtomicBool>}
impl Server{fn serve_connection(&self,_:())->Result<()>{SERVES.with(|v|v.set(v.get()+1));self.stopped.store(true,Ordering::Release);Ok(())}}
'''
TESTS = r'''
fn reset(secs:u64){CLOCK.with(|v|v.set(secs*1_000_000_000));WALL.with(|v|v.set(None));ACCEPTS.with(|v|v.set(0));SERVES.with(|v|v.set(0));}
fn calls()->(u32,u32){(ACCEPTS.with(Cell::get),SERVES.with(Cell::get))}
fn scoped(owner:&Arc<AtomicBool>,deadline:u64,source_wall:u64)->ScopedHistoryClockV1{let token=EphemeralCoordinatedHistoryLifetimeV1::capture_at(owner.clone(),Instant(deadline*1_000_000_000),source_wall,Instant(0),1000).unwrap();token.for_policy_at(owner,source_wall,Instant(0),1000).unwrap()}
#[test]fn old_120_loop_stops_before_late_first_read_new_fixed_scope_serves(){let stopped=Arc::new(AtomicBool::new(false));let gate=Arc::new(Mutex::new(false));let listener=Listener{fault:false,revoke:None};reset(121);old_loop(stopped.clone(),gate.clone(),listener,Server{stopped:stopped.clone()},Instant(120_000_000_000));assert_eq!(calls(),(0,0));reset(121);let owner=Arc::new(AtomicBool::new(false));let scope=scoped(&owner,500,900_000);new_loop(stopped.clone(),gate,Listener{fault:false,revoke:None},Server{stopped:stopped.clone()},scope.deadline(),Some(scope));assert_eq!(calls(),(1,1));}
#[test]fn default_scope_keeps_120_and_original_handler_path(){for secs in [119,120,121]{reset(secs);let stopped=Arc::new(AtomicBool::new(false));new_loop(stopped.clone(),Arc::new(Mutex::new(false)),Listener{fault:false,revoke:None},Server{stopped:stopped.clone()},Instant(120_000_000_000),None);assert_eq!(calls(),if secs<120{(1,1)}else{(0,0)});}}
#[test]fn original_stop_owner_source_wall_and_cutoff_refuse_acceptance(){for case in 0..5{reset(121);let stopped=Arc::new(AtomicBool::new(case==0));let owner=Arc::new(AtomicBool::new(false));let scope=scoped(&owner,500,900_000);match case{1=>owner.store(true,Ordering::Release),2=>WALL.with(|v|v.set(Some(900_000))),3=>WALL.with(|v|v.set(Some(999))),4=>CLOCK.with(|v|v.set(500_000_000_000)),_=>()};new_loop(stopped.clone(),Arc::new(Mutex::new(false)),Listener{fault:false,revoke:None},Server{stopped:stopped.clone()},scope.deadline(),Some(scope));assert_eq!(calls(),(0,0));}}
#[test]fn scoped_owner_drop_between_accept_and_handler_refuses_handler(){reset(121);let stopped=Arc::new(AtomicBool::new(false));let owner=Arc::new(AtomicBool::new(false));let scope=scoped(&owner,500,900_000);new_loop(stopped.clone(),Arc::new(Mutex::new(false)),Listener{fault:false,revoke:Some(owner)},Server{stopped:stopped.clone()},scope.deadline(),Some(scope));assert_eq!(calls(),(1,0));}
#[test]fn sealed_gate_and_accept_error_do_not_dispatch_or_restart(){for sealed in [true,false]{reset(499);let stopped=Arc::new(AtomicBool::new(false));let owner=Arc::new(AtomicBool::new(false));let scope=scoped(&owner,500,900_000);new_loop(stopped.clone(),Arc::new(Mutex::new(sealed)),Listener{fault:true,revoke:None},Server{stopped:stopped.clone()},scope.deadline(),Some(scope));assert_eq!(calls(),if sealed{(0,0)}else{(1,0)});}}
'''

def block(text,start):
    pos=text.index(start);brace=text.index('{',pos);depth=0
    for i in range(brace,len(text)):
        if text[i]=='{':depth+=1
        elif text[i]=='}':
            depth-=1
            if depth==0:return text[pos:i+1]
    raise AssertionError('unclosed source')
def digest(text):return hashlib.sha256(text.encode()).hexdigest()
def run(args,path,timeout):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
    path.write_text(result.stdout)
    if result.returncode:
        print(result.stdout[-16384:],file=sys.stderr)
        raise SystemExit(f'{path.name} failed: {result.returncode}')
    return result.stdout


def source_parity(root):
    base='crates/wholepact-authority/src/native_witness_owner/'
    source=(root/(base+'window/ephemeral_fixture_v1.rs')).read_text()
    norm=source.replace('#[path = "ephemeral_fixture_v1/coordinated_history_lifetime_v1.rs"]\nmod coordinated_history_lifetime_v1;\npub use coordinated_history_lifetime_v1::EphemeralCoordinatedHistoryLifetimeV1;\nuse coordinated_history_lifetime_v1::ScopedHistoryClockV1;\n','')
    a=norm.index('    /// Passive synthetic service restriction, not an action or journal grant.')
    z=norm.index('        // Keep the original bound endpoint',a)
    norm=norm[:a]+'    fn serve_exact_server(&self, server: AuthorityServer) -> Result<EphemeralHistoryServerV1> {\n'+norm[z:]
    norm=norm.replace('        let started = Instant::now();\n        let deadline = scope.as_ref().map_or(started + Duration::from_secs(120), |v| v.deadline());','        let deadline = Instant::now() + Duration::from_secs(120);')
    norm=norm.replace('\n                    if scope.as_mut().is_some_and(|v| v.check_current().is_err()) { break; }','').replace('\n                            if scope.as_mut().is_some_and(|v| v.check_current().is_err()) { break; }','')
    norm=norm.replace('            started,\n','').replace('    started: Instant,\n','')
    norm=norm.replace('    /// Uses the actual constructor start for either serving horizon; no server\n    /// lifetime, socket, source check or gate is touched.','    /// The start is derived from the same original 120-second constructor\n    /// interval; no server lifetime, socket, source check or gate is touched.')
    norm=norm.replace('        let age_us = Some(observed.saturating_duration_since(self.started).as_micros());','        let age_us = self\n            .deadline\n            .checked_sub(Duration::from_secs(120))\n            .map(|started| observed.saturating_duration_since(started).as_micros());')
    assert digest(norm)==BASELINES['fixture'], 'default server/ownership drift'
    delivery=(root/(base+'window/ephemeral_fixture_v1/durable_delivery_admission_v2.rs')).read_text()
    for name,arg in [('serve_committed_durable_delivery_history_v2','admission_operation_id'),('serve_original_delivery_bootstrap_history_v2','account_id')]:
        start=delivery.index('    pub fn '+name+'(');inner=block(delivery,'    fn '+name+'_inner(')
        finish=delivery.index(inner)+len(inner)
        body=inner[inner.index('{')+1:-1]
        body=body.replace('        let policy_expires_at_ms = {','        {').replace('            ledger.policy.policy_expires_at_ms\n        };','        }')
        tail='        let server = AuthorityServer::new(Arc::new(journal), self.tls.clone());\n        match lifetime {\n            Some(lifetime) => self.serve_exact_server_until(server, lifetime, policy_expires_at_ms),\n            None => self.serve_exact_server(server),\n        }'
        assert tail in body
        body=body.replace(tail,'        self.serve_exact_server(AuthorityServer::new(Arc::new(journal), self.tls.clone()))')
        original='    pub fn '+name+'(\n        &mut self,\n        '+arg+': &str,\n    ) -> Result<EphemeralHistoryServerV1> {'+body+'}'
        delivery=delivery[:start]+original+delivery[finish:]
    assert digest(delivery)==BASELINES['delivery'], 'original bootstrap/audit checks drift'
    host='crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/durable_proposal_v1/'
    external=(root/(host+'coordinated_external_witness_v1.rs')).read_text()
    assert external.index('let lifetime=') < external.index('for index in 0..2') < external.index('Event::BootstrapServing') < external.index('PostInputPhase::Ready')
    normalized=external.replace('original_cutoff:Instant,original_source_expires_at_ms:u64','original_cutoff:Instant').replace('    let lifetime=authority(witness.coordinated_history_lifetime_v1(original_cutoff,original_source_expires_at_ms))?;\n','').replace('serve_original_delivery_bootstrap_history_v2_until(&account_ids[index],&lifetime)','serve_original_delivery_bootstrap_history_v2(&account_ids[index])').replace('serve_committed_durable_delivery_history_v2_until(&actual_request.operation_id,&lifetime)','serve_committed_durable_delivery_history_v2(&actual_request.operation_id)')
    assert digest(normalized)==BASELINES['external'], 'external control/action/drain drift'
    full=(root/(host+'coordinated_full_fixture_v1.rs')).read_text()
    assert digest(full.replace('run(&terminal, witness, &account_ids, &root, cutoff, original.expiry_ms)?','run(&terminal, witness, &account_ids, &root, cutoff)?'))==BASELINES['full'], 'original fixture source/cutoff drift'
    transport=(root/'crates/wholepact-authority/src/transport.rs').read_text()
    assert digest(transport)==BASELINES['transport'], 'TLS/currentness/action transport drift'

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--run',action='store_true');a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    source_parity(a.source)
    base=a.source/'crates/wholepact-authority/src/native_witness_owner/window/ephemeral_fixture_v1.rs'
    source=base.read_text();life=(base.parent/'ephemeral_fixture_v1/coordinated_history_lifetime_v1.rs').read_text()
    loop=block(source,'while !stopped.load(Ordering::Acquire) && Instant::now() < deadline {')
    old=loop.replace('\n                    if scope.as_mut().is_some_and(|v| v.check_current().is_err()) { break; }','').replace('\n                            if scope.as_mut().is_some_and(|v| v.check_current().is_err()) { break; }','')
    assert digest(old)==OLD_LOOP_HASH
    assert 'self.serve_exact_server_inner(server, None)' in source
    assert 'let deadline = scope.as_ref().map_or(started + Duration::from_secs(120), |v| v.deadline());' in source
    assert 'self.construction_client_scope_revoked\n            .store(true, Ordering::Release)' in source
    transport=(a.source/'crates/wholepact-authority/src/transport.rs').read_text();assert 'const IO_TIMEOUT: Duration = Duration::from_secs(10);' in transport
    life='\n'.join(x for x in life.splitlines() if not x.startswith('//!') and x!='use super::*;').replace('pub(super) ','')
    gate=block(source,'fn accept_while_unsealed<T>')
    signature='(stopped:Arc<AtomicBool>,serving_accept_gate:Arc<Mutex<bool>>,listener:Listener,server:Server,deadline:Instant'
    rust=PREFIX+'\n'+life+'\n'+gate+'\nfn old_loop'+signature+') {'+old+'}\nfn new_loop'+signature+',mut scope:Option<ScopedHistoryClockV1>) {'+loop+'}\n'+TESTS
    target=a.out/'service-lifetime-trace.rs';target.write_text(rust)
    (a.out/'binding.json').write_text(json.dumps({'source':str(a.source),'files':{str(p.relative_to(a.source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [base,base.parent/'ephemeral_fixture_v1/coordinated_history_lifetime_v1.rs']},'old_loop_sha256':digest(old),'test_count':12,'limits':'inert clock/TCP/TLS, no socket/authority execution'},indent=2)+'\n')
    print(json.dumps({'generated':True,'executed':False,'tests':12}))
    if a.run:
        binary=a.out/'service-lifetime-tests';run(['rustc','--edition=2021','--test',str(target),'-o',str(binary)],a.out/'compile.log',60)
        listed=run([str(binary),'--list'],a.out/'list.log',10);names={line[:-6] for line in listed.splitlines() if line.endswith(': test')};assert names==EXPECTED_TESTS,(names,EXPECTED_TESTS)
        output=run([str(binary),'--test-threads=1'],a.out/'tests.log',30);assert '12 passed; 0 failed; 0 ignored' in output
        print(json.dumps({'executed':True,'tests':12}))

OLD_LOOP_HASH = '3b488e144ce535a765269a852cdbb30f15e03e733a39e87b414020a00d243e19'
EXPECTED_TESTS = {'tests::later_stage_wall_drift_cannot_refresh_narrower_policy_cap','tests::expired_zero_or_oversized_original_cutoff_is_refused', 'tests::original_source_and_actual_policy_caps_only_narrow', 'old_120_loop_stops_before_late_first_read_new_fixed_scope_serves', 'original_stop_owner_source_wall_and_cutoff_refuse_acceptance', 'tests::wall_rollback_and_expiry_refuse_without_refresh', 'sealed_gate_and_accept_error_do_not_dispatch_or_restart', 'scoped_owner_drop_between_accept_and_handler_refuses_handler', 'tests::late_stage_cannot_restart_expired_fixture_or_source', 'default_scope_keeps_120_and_original_handler_path', 'tests::fixed_service_survives_121_without_renewing_original_cutoff', 'tests::wrong_owner_and_owner_drop_revoke_existing_scope'}
BASELINES = {'fixture': '9842053ac94015c10e9fb4c154da8a1c86b06fe209a51469e686541a6b4ecea8', 'delivery': 'c5732e9b6d21a8ad2b5e643dde91fcef083fc6dc9e44a6eda560180ad50cc778', 'external': 'f916850659a5ffa3d055020c031923e02d695791958f6fcec06f24b690152762', 'full': '88daefaaaa935ad7ed8cce3e3891e6975fb84b98cce3081ae1e4a348bae8cc63', 'transport': '2c58ec5ae515ce13786ec81661901c9ba1c72a5f9827d3c925e4fbc48e4f2716'}
if __name__=='__main__':main()
