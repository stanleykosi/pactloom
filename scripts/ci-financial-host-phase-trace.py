#!/usr/bin/env python3
"""Extract Host phase/input controls into std-only before/after tests.

The UI, driver, native restriction, clock and owned-string adapters are inert.
No renderer, OS input, authority, socket, zeroization or runtime proof is made.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def block(text, marker):
    start = text.index(marker)
    at = text.index('{', start)
    depth, position = 1, at + 1
    tokens = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]', re.S)
    while depth:
        match = tokens.search(text, position)
        if not match:
            raise ValueError('unclosed block: ' + marker)
        if match.group() == '{': depth += 1
        elif match.group() == '}': depth -= 1
        position = match.end()
    return text[start:position]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--run', action='store_true')
    args = ap.parse_args()
    root, out = args.source.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources, pieces = [], []
    def read(path):
        data = (root / path).read_bytes()
        sources.append({'path': path, 'sha256': hashlib.sha256(data).hexdigest()})
        return data.decode()
    def bind(label, value):
        pieces.append({'label': label, 'sha256': hashlib.sha256(value.encode()).hexdigest()})
        return value
    ui = read('crates/wholepact-financial-coordinator/src/financial_source_ui.rs')
    hi = read('crates/wholepact-financial-coordinator/src/host_line_input.rs')
    # Source-bound rendezvous proof only: no actor or authority is executed.
    def ordered(text, markers, label):
        cursor = 0
        for marker in markers:
            cursor = text.index(marker, cursor) + len(marker)
        bind(label, text)
    signer_return = read('crates/wholepact-signer/src/authority_bridge/financial_result_ipc_v1/coordinated_return_v1.rs')
    return_prepare = block(signer_return, 'pub(crate) fn prepare(')
    ordered(return_prepare, ['&Response::Preview { preview }', 'read.finish_read()',
                             'Command::HostPrepared { preview_digest }', 'Ok(prepared)'],
            'Return preparation Preview then completed Read then HostPrepared before result')
    host_financial = read('crates/wholepact-native-host/src/host/financial/private_financial_v1.rs')
    intake = block(host_financial, 'fn intake_original_financial_result_kernel_v1<')
    ordered(intake, ['self.terminal.approve_historical(', 'self.terminal.approve_historical_original(',
                     '.approve_financial_intake_setup_original_v1(', 'receiver.receive_host()'],
            'Host original result intake has three separate approvals before receive_host')
    result_ipc = read('crates/wholepact-signer/src/authority_bridge/financial_result_ipc_v1.rs')
    ordered(block(result_ipc, 'fn receive_kernel('), ['&Command::HostPrepared {', 'FinancialResultStageV1::ReadyWait'],
            'Host receive kernel writes HostPrepared before Ready wait')
    host_export = read('crates/wholepact-native-host/src/host/financial/durable_delivery_admission_v2/closed_review_v3/coordinated_export_v1.rs')
    export = block(host_export, 'pub(in crate::host) fn private_original_coordinated_delivery_export_v1(')
    ordered(export, ['open_recipient(prepared.fixed_identity()', 'let final_inspection = source_checked_approval_v2(',
                     'self.terminal.approve_historical(', 'self.terminal.approve_durable_delivery_original_v3(',
                     'closed.deliver_coordinated_v1('],
            'Prepared recipient precedes distinct Host metadata and ExportExact approval then delivery')
    ordered(ui[ui.index('let out = self.native.admit_return_read('):],
            ['let out = self.native.admit_return_read(', 'self.transition(Phase::ReturnReading, frame)',
             'self.driver.borrow_mut().send_return_read(role, out)'], 'C Return Final then ReturnReading then worker send')
    ordered(ui[ui.index('let outbound = self.native.admit_v3_receive('):],
            ['let outbound = self.native.admit_v3_receive(', 'self.transition(Phase::V3Receiving, frame)',
             'self.driver.borrow_mut().send_v3_receive(role, outbound)'], 'C Receive Final then V3Receiving then worker send')
    phase = bind('Phase enum', block(ui, 'enum Phase {'))
    entry = bind('HostEntry enum', block(ui, 'enum HostEntry {'))
    after = bind('actual phase allowlist', block(ui, 'fn host_phase_allows_input('))
    # Remove only the approved variant and its commentary. The reconstructed
    # pre-fix helper must match the independently read frozen P46 exact bytes.
    before = '\n'.join(line for line in after.splitlines()
                       if not line.lstrip().startswith('//') and '| Phase::V3Receiving' not in line and '| Phase::ReturnReading' not in line)
    assert hashlib.sha256(before.encode()).hexdigest() == '87d982e06f26c78131d3781c6127952332bd84347f200cf099a710c188f1b60b'
    bind('exact P46 phase allowlist', before)
    helpers = '\n'.join(bind(marker, block(ui, marker)) for marker in [
        'fn host_entry_blocks_source(', 'fn tail_eligible('])
    draw = block(ui, 'fn draw_host(')
    draw_controls = bind('draw_host literal control match', block(draw, 'match self.host_entry {'))
    outer_start = ui.index('            if !self.focused_last { ui.label("Private source and review details are hidden while unfocused."); return; }')
    outer_end = ui.index('            let later_frame', outer_start)
    outer = bind('literal outer focus/draw/protected-source gate', ui[outer_start:outer_end])
    intent_start = ui.index('            Intent::BeginHostLine\n')
    intent_end = ui.index('            Intent::SaveContinuationSelector', intent_start)
    intent = bind('literal BeginHostLine arm', ui[intent_start:intent_end])
    intent_preamble = bind('literal apply_intent protected-source precondition', block(block(ui,'fn apply_intent('), 'if host_entry_blocks_source(self.host_entry)'))
    context = bind('literal output edit-context check', block(ui, 'fn check_host_edit_context('))
    tail_start = ui.index('        self.check_current();\n        self.check_host_edit_context();')
    tail_end = ui.index('        (self.read_to_end, self.acknowledged)', tail_start)
    tail_head = bind('literal Host finish/tail eligibility statements', ui[tail_start:tail_end])
    tail_start = ui.index('        if !eligible || self.terminal() {', tail_end)
    tail_end = ui.index('        // The real Arm click', tail_start)
    tail = bind('literal Host submit and source-dispatch tail', ui[tail_start:tail_end])
    host_methods = '\n'.join(bind('HostLineInput ' + marker, block(hi, marker)) for marker in [
        'pub(super) fn new(', 'pub(super) fn status(', 'fn open(', 'pub(super) fn finish_frame(',
        'pub(super) fn cancel(', 'fn check_current(', 'fn observe(', 'fn close_restricted(', 'fn close(', 'fn scrub_closed_frame('])
    into = bind('SubmittedHostLine actual one-use extraction', block(hi, 'pub(super) fn into_line_for('))
    host_helpers = '\n'.join(bind(marker, block(hi, marker)) for marker in ['fn eligible_pass(', 'fn valid_line('])
    status = bind('HostLineStatus enum', block(hi, 'pub(super) enum HostLineStatus {'))
    # Exact original eligibility and Submit statements; TextEdit/render/raw-event
    # adapter intentionally omitted, with admission explicitly supplied in tests.
    show = block(hi, 'pub(super) fn show(')
    start = show.index('        let admitted_batch =')
    end = show.index('        if !eligible {', start)
    show_eligible = bind('actual input show eligibility statements', show[start:end])
    start = show.index('        let submit_response =')
    show_submit = show[start:show.rfind('\n    }')]
    show_submit = bind('actual input Submit button statements', show_submit)
    common = r'''
use std::{cell::{Cell,RefCell},rc::Rc,any::{Any,TypeId},collections::HashMap,ops::{Deref,DerefMut}};
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]struct Instant(u64);
thread_local!{static NOW:Cell<u64>=const{Cell::new(10)};}
impl Instant{fn now()->Self{Self(NOW.with(Cell::get))}}
type Result<T>=std::result::Result<T,&'static str>;
fn rejected(s:&'static str)->&'static str{s}
macro_rules! boundary {($($x:tt)*)=>{()};}
macro_rules! ci_response {($ui:expr,$response:expr,$($rest:tt)*)=>{$response};}
// String ownership only: NOT a zeroization implementation or secrecy claim.
#[derive(Default)]struct Zeroizing<T>(T);
impl<T> Zeroizing<T>{fn new(v:T)->Self{Self(v)}}
impl<T>Deref for Zeroizing<T>{type Target=T;fn deref(&self)->&T{&self.0}}
impl<T>DerefMut for Zeroizing<T>{fn deref_mut(&mut self)->&mut T{&mut self.0}}
impl Zeroizing<String>{fn zeroize(&mut self){self.0.clear()}}
const MAX_LINE_BYTES:usize=8192;
#[derive(Clone)]struct WidgetLease;
#[derive(Clone,Copy)]struct RawFacts{focused:bool,blur:bool,escape:bool,close:bool}
mod egui {
 use super::*;
 #[derive(Clone,Copy)]pub enum PointerButton{Primary}
 #[derive(Clone)]pub enum Event{Blur,Escape,Payload}
 pub struct RawInput{pub facts:Option<RawFacts>,pub events:Vec<Event>}
 pub struct Input{pub focused:bool,pub raw:RawInput,pub events:Vec<Event>}
 #[derive(Default)]pub struct Data(HashMap<(u64,TypeId),Box<dyn Any>>);
 impl Data{pub fn get_temp<T:Clone+'static>(&self,id:u64)->Option<T>{self.0.get(&(id,TypeId::of::<T>())).and_then(|v|v.downcast_ref::<T>()).cloned()}pub fn insert_temp<T:'static>(&mut self,id:u64,v:T){self.0.insert((id,TypeId::of::<T>()),Box::new(v));}}
 pub struct Inner{pub frame:Cell<u64>,pub discard:Cell<bool>,pub input:RefCell<Input>,pub data:RefCell<Data>}
 #[derive(Clone)]pub struct Context(pub Rc<Inner>);
 impl Context{pub fn new()->Self{Self(Rc::new(Inner{frame:Cell::new(1),discard:Cell::new(false),input:RefCell::new(Input{focused:true,raw:RawInput{facts:Some(RawFacts{focused:true,blur:false,escape:false,close:false}),events:vec![]},events:vec![]}),data:RefCell::new(Data::default())}))}pub fn cumulative_frame_nr(&self)->u64{self.0.frame.get()}pub fn will_discard(&self)->bool{self.0.discard.get()}pub fn input<T>(&self,f:impl FnOnce(&Input)->T)->T{f(&self.0.input.borrow())}pub fn input_mut<T>(&self,f:impl FnOnce(&mut Input)->T)->T{f(&mut self.0.input.borrow_mut())}pub fn data_mut<T>(&self,f:impl FnOnce(&mut Data)->T)->T{f(&mut self.0.data.borrow_mut())}}
 pub struct Response(bool);impl Response{pub fn clicked_by(&self,_:PointerButton)->bool{self.0}}
 pub struct Button(&'static str);impl Button{pub fn new(s:&'static str)->Self{Self(s)}}
 pub struct Ui{pub begin:bool,pub submit:bool,pub enabled:bool,pub visible:bool,pub sizing:bool,pub labels:Vec<String>,pub buttons:Vec<&'static str>}
 impl Ui{pub fn new()->Self{Self{begin:false,submit:false,enabled:true,visible:true,sizing:false,labels:vec![],buttons:vec![]}}pub fn label(&mut self,s:impl ToString){self.labels.push(s.to_string())}pub fn button(&mut self,s:&'static str)->Response{self.buttons.push(s);Response(self.begin&&self.enabled&&self.visible)}pub fn add_enabled(&mut self,e:bool,b:Button)->Response{self.buttons.push(b.0);Response(e&&self.submit)}pub fn is_enabled(&self)->bool{self.enabled}pub fn is_visible(&self)->bool{self.visible}pub fn is_sizing_pass(&self)->bool{self.sizing}}
}
fn widget_id()->u64{1}
fn clear_widget(_:&egui::Context){}
fn scrub_context_payloads(ctx:&egui::Context){ctx.input_mut(|i|{i.events.clear();i.raw.events.clear()});}
fn clear_sensitive_output(_:&egui::Context,_:bool){}
fn scrub_payloads(events:&mut Vec<egui::Event>){events.clear()}
fn raw_facts(raw:&egui::RawInput)->Option<RawFacts>{raw.facts}
fn is_blur(e:&egui::Event)->bool{matches!(e,egui::Event::Blur)}
fn is_escape(e:&egui::Event)->bool{matches!(e,egui::Event::Escape)}
struct SubmittedHostLine{ordinal:u64,original_deadline:Instant,line:Zeroizing<String>}
struct HostLineInput{ctx:egui::Context,ordinal:u64,original_deadline:Instant,line:Zeroizing<String>,status:HostLineStatus,focus_seen:bool,focused_last:bool,raw_input_allowed:bool,submit_frame:Option<u64>}
#[derive(Clone,Copy,PartialEq,Eq)]enum OutputState{Open,Closed}
struct Output{revision:u64,complete:bool,state:OutputState}
impl Output{fn revision(&self)->u64{self.revision}fn decode_complete(&self)->bool{self.complete}fn state(&self)->OutputState{self.state}}
#[derive(Default)]struct Native{revoked:Cell<bool>}
impl Native{fn revoke(&self){self.revoked.set(true)}}
#[derive(Default)]struct Driver{queued:Vec<(u64,String)>,fail:bool}
impl Driver{fn send_host_line(&mut self,n:u64,line:Zeroizing<String>)->std::result::Result<(),Zeroizing<String>>{if self.fail{Err(line)}else{self.queued.push((n,line.0));Ok(())}}}
#[derive(Clone,Copy)]enum Intent{BeginHostLine,SourceAction}
struct Window{phase:Phase,host_entry:HostEntry,host_ordinal:u64,host_edit_revision:Option<u64>,host_input:Option<HostLineInput>,host_output:Output,password:Option<()>,session_deadline:Instant,focused_last:bool,intent:Option<Intent>,native:Native,driver:RefCell<Driver>,last_tail_frame:Option<u64>,source_actions:usize,draws:usize}
impl Window{
 fn new(phase:Phase)->Self{Self{phase,host_entry:HostEntry::Idle,host_ordinal:0,host_edit_revision:None,host_input:None,host_output:Output{revision:4,complete:true,state:OutputState::Open},password:None,session_deadline:Instant(1000),focused_last:true,intent:None,native:Native::default(),driver:RefCell::new(Driver::default()),last_tail_frame:None,source_actions:0,draws:0}}
 fn terminal(&self)->bool{matches!(self.phase,Phase::Revoked|Phase::Finished)}
 // Inert native/currentness adapter: no actor, clock or authority is minted.
 fn check_current(&mut self){if self.native.revoked.get(){self.revoke("restricted")}}
 fn revoke(&mut self,_:&'static str){self.native.revoke();if let Some(input)=&mut self.host_input{input.cancel(&mut||self.native.revoke())}self.host_entry=HostEntry::Closed;self.phase=Phase::Revoked;}
 fn submit_password(&mut self,_:(),_:u64)->Result<()>{self.source_actions+=1;Ok(())}
 fn history_retirement_tail(&mut self)->Result<()>{Ok(())}
'''
    methods = '\n'+context+'\nfn draw_host(&mut self,ui:&mut egui::Ui){self.draws+=1;\n'+draw_controls+'\n}\nfn draw_window(&mut self,ui:&mut egui::Ui){\n'+outer+'\n}\n'
    methods += 'fn apply_intent(&mut self,intent:Intent,_frame:u64,ctx:&egui::Context)->Result<()> {\n'+intent_preamble+'\nmatch intent {\n'+intent+'Intent::SourceAction => {self.source_actions+=1;},\n_ => return Err(rejected("stale source-action intent")),\n} Ok(())\n}\n'
    methods += 'fn tail(&mut self,frame:u64,visible:bool,ctx:&egui::Context){\n'+tail_head+'\nlet password:Option<()>=None;\n'+tail+'\n}\n}\n'
    host_impl = '\nimpl HostLineInput {\n'+host_methods+'\nfn show(&mut self,ui:&mut egui::Ui,expected:u64,restrict:&mut impl FnMut()){self.check_current(expected,restrict);if !self.open(){return;}\n'+show_eligible+'\n'+show_submit+'\n}\n}\nimpl SubmittedHostLine{\n'+into+'\n}\n'
    tests = r'''
fn reset(){NOW.with(|n|n.set(10));}
fn start_phase(phase:Phase)->(Window,egui::Context){reset();let ctx=egui::Context::new();let mut w=Window::new(phase);let mut ui=egui::Ui::new();ui.begin=true;w.draw_window(&mut ui);w.tail(1,true,&ctx);assert_eq!(w.host_entry,HostEntry::Editing(1));(w,ctx)}
fn start()->(Window,egui::Context){start_phase(if FIXED{Phase::V3Receiving}else{Phase::Selecting})}
fn submit(w:&mut Window,ctx:&egui::Context){submit_at(w,ctx,2)}
fn submit_at(w:&mut Window,ctx:&egui::Context,frame:u64){ctx.0.frame.set(frame);let input=w.host_input.as_mut().unwrap();input.line=Zeroizing::new("synthetic user line".into());input.raw_input_allowed=true;let mut ui=egui::Ui::new();ui.submit=true;w.draw_window(&mut ui);}
#[test]fn approved_wait_phases_before_cannot_draw_or_begin_after_can(){for phase in [Phase::V3Receiving,Phase::ReturnReading]{reset();let ctx=egui::Context::new();let mut w=Window::new(phase);let mut ui=egui::Ui::new();ui.begin=true;w.draw_window(&mut ui);assert_eq!(w.draws,usize::from(FIXED));w.tail(1,true,&ctx);assert_eq!(w.host_entry,if FIXED{HostEntry::Editing(1)}else{HostEntry::Idle});let mut direct=Window::new(phase);assert_eq!(direct.apply_intent(Intent::BeginHostLine,1,&egui::Context::new()).is_ok(),FIXED);}}
#[test]fn password_and_exact_review_phases_remain_denied(){reset();for p in [Phase::Password,Phase::V3Password,Phase::V3ReceiveReview,Phase::V3PrepareReadReview,Phase::V3PairReview,Phase::V3EnrollmentReview,Phase::V3ManifestReview,Phase::V3RediscloseReview,Phase::ReturnReadReview,Phase::ReturnPrepared,Phase::ReturnExactReview,Phase::ReturningExact]{let mut w=Window::new(p);let mut ui=egui::Ui::new();ui.begin=true;w.draw_window(&mut ui);assert_eq!(w.draws,0);assert!(w.apply_intent(Intent::BeginHostLine,1,&egui::Context::new()).is_err());}}
#[test]fn existing_password_slot_prevents_begin(){reset();let mut w=Window::new(Phase::Selecting);w.password=Some(());assert!(w.apply_intent(Intent::BeginHostLine,1,&egui::Context::new()).is_err());assert_eq!(w.host_entry,HostEntry::Idle);}
#[test]fn normal_user_submit_is_one_shot_and_enters_writing(){for phase in if FIXED{[Phase::V3Receiving,Phase::ReturnReading]}else{[Phase::Selecting,Phase::Selecting]}{let(mut w,ctx)=start_phase(phase);submit(&mut w,&ctx);w.tail(2,true,&ctx);assert_eq!(w.host_entry,HostEntry::Writing(1));assert_eq!(w.host_input.as_ref().unwrap().status(),HostLineStatus::Submitted);assert_eq!(w.driver.borrow().queued.len(),1);assert_eq!(w.driver.borrow().queued[0],(1,"synthetic user line".into()));ctx.0.frame.set(3);w.tail(3,true,&ctx);assert_eq!(w.driver.borrow().queued.len(),1);assert_eq!(w.source_actions,0);}}
#[test]fn unfocused_hidden_discarded_and_repeated_tails_do_not_queue(){for mode in 0..4{let(mut w,ctx)=start();submit(&mut w,&ctx);let mut visible=true;match mode{0=>w.focused_last=false,1=>visible=false,2=>ctx.0.discard.set(true),_=>w.last_tail_frame=Some(2)};w.tail(2,visible,&ctx);assert!(w.driver.borrow().queued.is_empty());}}
#[test]fn input_focus_loss_and_invalid_viewport_deny(){for mode in 0..3{let(mut w,ctx)=start();submit(&mut w,&ctx);ctx.input_mut(|i|match mode{0=>{i.focused=false;i.raw.facts.as_mut().unwrap().focused=false},1=>i.raw.facts=None,_=>i.events.push(egui::Event::Escape)});w.tail(2,true,&ctx);assert!(w.driver.borrow().queued.is_empty());assert!(w.native.revoked.get());}}
#[test]fn expired_deadline_or_ordinal_change_restricts_one_use_line(){for mode in 0..2{let(mut w,ctx)=start();submit(&mut w,&ctx);if mode==0{NOW.with(|n|n.set(1000))}else{w.host_entry=HostEntry::Editing(2)}w.tail(2,true,&ctx);assert!(w.driver.borrow().queued.is_empty());assert!(w.native.revoked.get());}for (ordinal,deadline) in [(2,1000),(1,10)]{reset();let submitted=SubmittedHostLine{ordinal,original_deadline:Instant(deadline),line:Zeroizing::new("synthetic".into())};let mut revoked=false;assert!(submitted.into_line_for(1,&mut||revoked=true).is_none());assert!(revoked);}}
#[test]fn changed_revision_decode_or_output_state_discards_editor(){for mode in 0..3{let(mut w,ctx)=start();submit(&mut w,&ctx);match mode{0=>w.host_output.revision+=1,1=>w.host_output.complete=false,_=>w.host_output.state=OutputState::Closed};w.tail(2,true,&ctx);assert!(w.driver.borrow().queued.is_empty());assert!(w.native.revoked.get());}}
#[test]fn editing_and_partial_write_block_source_action_and_another_begin(){let(mut w,ctx)=start();w.intent=Some(Intent::SourceAction);ctx.0.frame.set(2);w.tail(2,true,&ctx);assert_eq!(w.source_actions,0);assert!(w.apply_intent(Intent::SourceAction,2,&ctx).is_err());assert!(w.apply_intent(Intent::BeginHostLine,2,&ctx).is_err());submit_at(&mut w,&ctx,3);w.tail(3,true,&ctx);assert_eq!(w.host_entry,HostEntry::Writing(1));w.intent=Some(Intent::SourceAction);ctx.0.frame.set(4);w.tail(4,true,&ctx);assert_eq!(w.source_actions,0);assert!(w.apply_intent(Intent::BeginHostLine,4,&ctx).is_err());assert_eq!(w.driver.borrow().queued.len(),1);}
#[test]fn queue_failure_restricts_without_retry(){let(mut w,ctx)=start();w.driver.borrow_mut().fail=true;submit(&mut w,&ctx);w.tail(2,true,&ctx);assert!(w.native.revoked.get());assert_eq!(w.host_entry,HostEntry::Closed);assert!(w.driver.borrow().queued.is_empty());ctx.0.frame.set(3);w.tail(3,true,&ctx);assert!(w.driver.borrow().queued.is_empty());}
#[test]fn expired_constructor_context_and_ordinal_overflow_deny(){for mode in 0..4{reset();let mut w=Window::new(Phase::Selecting);match mode{0=>w.session_deadline=Instant(10),1=>w.host_ordinal=u64::MAX,2=>w.host_output.complete=false,_=>w.host_output.state=OutputState::Closed};assert!(w.apply_intent(Intent::BeginHostLine,1,&egui::Context::new()).is_err());assert_eq!(w.host_entry,HostEntry::Idle);}}
#[test]fn actual_submit_eligibility_rejects_sizing_disabled_hidden_unadmitted(){for mode in 0..4{let(mut w,ctx)=start();ctx.0.frame.set(2);let input=w.host_input.as_mut().unwrap();input.raw_input_allowed=mode!=3;let mut ui=egui::Ui::new();ui.submit=true;match mode{0=>ui.sizing=true,1=>ui.enabled=false,2=>ui.visible=false,_=>()};w.draw_window(&mut ui);w.tail(2,true,&ctx);assert!(w.driver.borrow().queued.is_empty());}}
'''
    assembled = []
    for name, fixed, allow in [('before',False,before),('after',True,after)]:
        assembled.append('mod '+name+' {\nconst FIXED:bool='+str(fixed).lower()+';\n'+common+'\n')
        # End Window impl before adding types/functions; literal methods then
        # reopen it. pub(super) input methods stay in their genuine child scope.
        assembled[-1] += '}\n#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'+phase+'\n#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'+entry+'\n#[derive(Clone,Copy,Debug,PartialEq,Eq)]\n'+status+'\n'+allow+'\n'+helpers+'\n'+host_helpers+'\nimpl Window{\n'+methods+host_impl+tests+'\n}\n'
    harness = '#![allow(dead_code,unused_imports,unused_mut)]\n' + ''.join(assembled)
    assert len(re.findall(r'#\[test\]',harness)) == 24
    path = out/'host-phase-trace.rs';path.write_text(harness)
    binding={'version':1,'sources':sources,'literal_pieces':pieces,'tests':24,'before_tests':12,'after_tests':12,'harness_sha256':hashlib.sha256(harness.encode()).hexdigest(),'executed':False,'limits':['UI controls, native restriction, driver queue, context, clock and owned-string adapters are inert.','Actual text-edit rendering, raw event parser, credentials, real native authority, OS input, zeroization, and PTY writes are not executed.','Literal phase/focus/draw-control/Begin/finish/submit-tail methods and predicates are extracted; unrelated review-progress statements are not modeled.']}
    if args.run:
        executable=out/'host-phase-trace-tests'
        def run(command,timeout,log):
            done=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
            (out/log).write_text(done.stdout)
            if done.returncode:print(done.stdout,end='');raise SystemExit(done.returncode)
            return done.stdout
        run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test',str(path),'-o',str(executable)],60,'compile.log')
        listing=run([str(executable),'--list'],10,'list.log')
        names=[line[:-6] for line in listing.splitlines() if line.endswith(': test')]
        expected=[f'{module}::{name}' for module in ['before','after'] for name in re.findall(r'#\[test\]\s*fn (\w+)\(',tests)]
        if len(names)!=24 or set(names)!=set(expected):raise SystemExit('exact 24-test listing mismatch')
        print(run([str(executable),'--test-threads=1'],30,'tests.log'),end='')
        binding['executed']=True
    (out/'host-phase-source-bindings.json').write_text(json.dumps(binding,indent=2)+'\n')
    print(json.dumps({'tests':24,'before':12,'after':12,'executed':args.run}))


if __name__=='__main__':main()
