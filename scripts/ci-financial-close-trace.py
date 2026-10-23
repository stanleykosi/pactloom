from pathlib import Path
import hashlib,json
import argparse
parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--run',action='store_true');args=parser.parse_args();new=args.source;out=args.out;out.mkdir(parents=True,exist_ok=True)
paths=['crates/wholepact-financial-coordinator-origin/src/signer_continue_state.rs','crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs','crates/wholepact-financial-coordinator-origin/src/financial_observer.rs','crates/wholepact-financial-coordinator-origin/src/financial_ci_actor_diagnostics.rs']
def item(text,needle):
 p=text.index(needle); start=text.index('{',p); n=1;i=start+1
 while n:
  if text[i]=='{':n+=1
  elif text[i]=='}':n-=1
  i+=1
 return text[p:i]
cs=(new/paths[0]).read_text();fs=(new/paths[1]).read_text();obs=(new/paths[2]).read_text();diag=(new/paths[3]).read_text()
current='\n'.join(item(cs,k) for k in ['pub(super) fn close(&self)','pub(super) fn close_with_failure_observation','fn close_after_restriction'])
# Exact baseline bodies from published c5b8bb38c51af58a14f0cb20845231ae9fbf4e3c.
prior='pub(super) fn close_old(&self) {\n        self.phase.revoke();\n        self.alive.store(false, Ordering::Release);\n        self.peer.shutdown();\n    }'
origin=item(fs,'pub fn close_for_failed_worker_v1').replace('fn close_for_failed_worker_v1','fn close_current')
oldorigin='pub fn close_prior(&mut self){\n        self.failed=true;\n        let _=self.restrict();\n        self.core.close_old();\n        self.leaf.take();\n    }'
reporter=item(diag,'impl Reporter {')
best=item(obs,'fn best_effort_actor_observation')
text='''#![allow(dead_code,unused_imports)]
// Exact close methods and Reporter; inert state/transport carriers only. No
// real actors, sockets, observer filesystem, scheduler or authority are used.
use std::sync::atomic::Ordering;
use std::cell::RefCell;
thread_local!{static EVENTS:RefCell<Vec<&'static str>>=RefCell::new(Vec::new());static MODE:RefCell<u8>=RefCell::new(0);static STATE:RefCell<(Reporter,Option<FailureFacts>)>=RefCell::new((Reporter::default(),None));}
fn event(e:&'static str){EVENTS.with(|x|x.borrow_mut().push(e));}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct FailureFacts{driver:u8,listener:Option<u8>}
#[derive(Clone,Copy)]struct ReapFacts;
#[derive(Clone,Copy,Default)]struct Reporter{failure_attempted:bool,reap_attempted:u32,failed:bool}
'''+reporter+'''
mod financial_observer {
 use super::*;
'''+best+'''
 pub(crate) fn financial_ci_flush_actor_failure_before_edge_close(){
  best_effort_actor_observation(||{
   STATE.with(|s|{let mut s=s.borrow_mut();let f=s.1;s.0.flush_failure(f,|_|{event("observe");MODE.with(|m|match *m.borrow(){1=>Err(()),2=>panic!("synthetic observer panic"),_=>Ok(())})});});
  });
 }
}
mod kernel {
 use super::*;
 struct Phase;impl Phase{fn revoke(&self){event("revoke");}}
 struct Alive;impl Alive{fn store(&self,_:bool,_:Ordering){event("alive_false");}}
 struct Peer;impl Peer{fn shutdown(&self){event("shutdown");}}
 pub(super) struct Core{phase:Phase,alive:Alive,peer:Peer}
 impl Core {
'''+current+'\n'+prior+'''
 }
 struct Leaf;impl Leaf{fn take(&mut self)->Option<()> {event("leaf_take");None}}
 pub(super) struct Origin{failed:bool,core:Core,leaf:Leaf}
 impl Origin {
  pub(super) fn new()->Self{Self{failed:false,core:Core{phase:Phase,alive:Alive,peer:Peer},leaf:Leaf}}
  fn restrict(&mut self)->Result<(),()>{event("restrict");Err(())}
'''+origin+'\n'+oldorigin+'''
  pub(super) fn ordinary_close(&self){self.core.close();}
 }
}
fn reset(mode:u8,failed:bool){EVENTS.with(|e|e.borrow_mut().clear());MODE.with(|m|*m.borrow_mut()=mode);STATE.with(|s|*s.borrow_mut()=(Reporter::default(),failed.then_some(FailureFacts{driver:7,listener:Some(9)})));}
fn run(prior:bool,mode:u8)->Vec<&'static str>{reset(mode,true);event("driver_error");let mut o=kernel::Origin::new();if prior{o.close_prior()}else{o.close_current()};event("join");EVENTS.with(|e|e.borrow().clone())}
#[test]fn exact_old_new_failure_order_preserved(){let old=run(true,0);let new=run(false,0);assert_eq!(new,vec!["driver_error","restrict","revoke","alive_false","observe","shutdown","leaf_take","join"]);assert_eq!(new.into_iter().filter(|x|*x!="observe").collect::<Vec<_>>(),old);}
#[test]fn append_error_and_unwind_still_shutdown_once(){for mode in [1,2]{let trace=run(false,mode);assert_eq!(trace.iter().filter(|x|**x=="shutdown").count(),1);assert_eq!(&trace[trace.len()-3..],["shutdown","leaf_take","join"]);}}
#[test]fn ordinary_close_and_ungated_cleanup_emit_nothing(){for failed in [false,true]{reset(0,failed);kernel::Origin::new().ordinary_close();assert_eq!(EVENTS.with(|e|e.borrow().clone()),["revoke","alive_false","shutdown"]);}reset(0,false);kernel::Origin::new().close_current();assert!(!EVENTS.with(|e|e.borrow().contains(&"observe")));}
#[test]fn early_snapshot_is_once_and_final_never_retries(){for mode in [0,1]{run(false,mode);financial_observer::financial_ci_flush_actor_failure_before_edge_close();assert_eq!(EVENTS.with(|e|e.borrow().iter().filter(|x|**x=="observe").count()),1);}}
#[test]fn edge_kill_window_old_loses_new_preserves(){let old=run(true,0);let new=run(false,0);let before_edge=|v:Vec<&'static str>|v.into_iter().take_while(|x|*x!="shutdown").collect::<Vec<_>>();assert!(!before_edge(old).contains(&"observe"));assert!(before_edge(new).contains(&"observe"));}
'''
(out/'signer-close-trace.rs').write_text(text)
(out/'source-binding.json').write_text(json.dumps({'baseline_commit':'c5b8bb38c51af58a14f0cb20845231ae9fbf4e3c','candidate':{p:hashlib.sha256((new/p).read_bytes()).hexdigest() for p in paths}},indent=2)+'\n')
print('generated exact-source std-only harness; NOT executed')

if args.run:
 import os,subprocess,sys
 for script in ['ci-financial-witness-close-trace.py','ci-financial-export-trace.py']:
  subprocess.run([sys.executable,'-I','-B',str(new/'scripts'/script),'--source',str(new),'--out',str(out)],check=True,timeout=30)
 rustc=os.environ.get('RUSTC','rustc')
 for name,semantic,expected in [('signer-close-trace',True,5),('authority-owner-harness',False,5),('witness-close-harness',True,18),('host-export-trace',True,5)]:
  cmd=[rustc,'--edition=2021','--test',str(out/(name+'.rs')),'-o',str(out/(name+'-tests'))]
  if semantic:cmd+=['--cfg','wholepact_financial_rendered_host_semantic_ci']
  subprocess.run(cmd,check=True,timeout=60)
  binary=str((out/(name+'-tests')).resolve())
  listed=subprocess.run([binary,'--list'],check=True,capture_output=True,text=True,timeout=10).stdout
  assert sum(line.endswith(': test') for line in listed.splitlines())==expected,(name,listed)
  subprocess.run([binary,'--test-threads=1'],check=True,timeout=30)
