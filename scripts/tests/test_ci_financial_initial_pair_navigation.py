"""Actual FullFlow/NativeScenario with inert render/input edges, not Pair authority."""
import contextlib
import copy
import importlib.util
import pathlib
import sys
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('initial_pair_flow_tested',ROOT/'ci-financial-flow.py')
F=importlib.util.module_from_spec(spec);sys.modules[spec.name]=F;spec.loader.exec_module(F)
PREPARATION=F.PAIR_PREPARATION_PURPOSE
PAIR=F.PAIR_CONFIRMATION_PURPOSE

def prompt(detail,number):
 return detail+'\nType APPROVE '+format(number,'016x')+' to approve this exact operation, or anything else to reject: '

class PairNavigationTests(unittest.TestCase):
 def model(self,owner='Signer1',profile=None,*,module=None,submit_failure=False,type_failure=False,render_failure=False,visible_pair=False,clipped=False,pair_detail=PAIR):
  m=module or F;profile=profile or m.C.SEMANTIC_PROFILE
  class ReachedPair(Exception):pass
  state=dict(generation=0,clock=1_000_000_000,mode='Idle',remaining=0,ordinal=0,revision=1,end=0,
             text='Waiting for local preparation.\n',stage='Waiting',line=None,submitted=[],bottom=False,
             pair_at=0 if visible_pair else None,pair_clicked=False,wheels=[],bounds=[],events=[],clipped=clipped,coverage=0,
             failure=OSError('inert control failure'))
  if visible_pair:state['bottom']=True
  state['end']=m.H.count(state['text']);deadline=301_000_000_000
  records=[dict(kind='SignerMilestone',facts=dict(owner=owner,step='EntryOpened'))]
  if owner=='Signer2':records += [dict(kind='SignerMilestone',facts=dict(owner='Signer1',step='SigningRetired')),
                                dict(kind='HostMilestone',facts=dict(step='Owner1SigningRetired'))]
  def publish(stage,text):
   state.update(stage=stage,text=text,revision=state['revision']+1,end=state['end']+m.H.count(text),coverage=0)
  def crop():
   if state['clipped'] and state['stage'] in ('Preparation','Pair') and state['coverage']<2:
    return state['text'][state['text'].index('Type APPROVE '):]
   return state['text']
  self_outer=self
  class Observer:
   expected_profile=profile
   def read(self):
    g=state['generation']
    if state['stage']=='Waiting' and g>=90:publish('Preparation',prompt(PREPARATION,1))
    elif state['stage']=='Preparing' and g>=state['next_prompt']:publish('Pair',prompt(pair_detail,2))
    if state['stage']=='Preparing':self_outer.assertFalse(getattr(flow,'pair_navigation_submitted',{}))
    return records
   def host_view(self,s):
    h=s['host_observation'];v=dict(id=s['host_view_id'],view_generation=s['view_generation'],revision=h['revision'],nonws_end=h['nonws_end'],view=h['view'],text=crop())
    m.C.match_host_view(s,v);return v['text']
   def next_snapshot(self,bound):
    if state['pair_clicked']:raise ReachedPair()
    state['bounds'].append(bound);state['generation']+=1;state['clock']+=200_000_000
    m.C.require(state['clock']<bound,'deadline')
    if state['mode']=='Writing':
     if state['remaining']:state['remaining']-=1
     else:
      state['mode']='Idle'
      if state['stage']=='Preparation':
       publish('Preparing','Preparing the actual original recipient.\n');state['next_prompt']=state['generation']+30
    editing=state['mode']=='Editing';protected=state['mode']!='Idle'
    host_visible=not state['bottom'] or state['pair_at'] is None
    ws=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,800])]
    if editing:ws += [dict(tag=t,owner=None,enabled=True,rect=[10,y,110,y+20]) for t,y in [('HostEditor',100),('HostSubmit',150)]]
    elif not protected and host_visible:ws += [dict(tag='HostOutput',owner=None,enabled=True,rect=[10,200,1100,440]),dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,460,210,490])]
    if not protected and state['bottom'] and state['pair_at'] is not None and state['generation']>=state['pair_at']:
     ws.append(dict(tag='ReviewV3Pair',owner=owner,enabled=True,rect=[10,700,210,730]))
    h=dict(revision=state['revision'],nonws_end=state['end'],context_valid=True,entry=state['mode'],
           editor=dict(ordinal=state['ordinal'],revision=state['revision']) if editing else None,
           view=dict(rect=[10,200,1100,440],nonws=m.H.count(crop()),rows=8) if not protected and host_visible else None)
    s=dict(phase='Selecting',subphase='None',owner=None,view_generation=state['generation'],focused=True,
           secret_input=False,host_input=protected,pixels_per_point=1,viewport=[1280,800],widgets=ws,host_observation=h)
    if profile==m.C.SEMANTIC_PROFILE:s['host_view_id']=state['revision'] if h['view'] is not None else None
    return s
  controller=mock.Mock();fixture=mock.Mock(deadline_ns=deadline)
  fixture.check.side_effect=lambda:m.C.require(state['clock']<deadline,'deadline')
  fixture.source_path.return_value='/nonexistent-inert-pair-navigation-selector'
  def click(x,y):
   if y==475:
    self.assertEqual(state['mode'],'Idle')
    # Inert geometry adapter: protected Host rendering omits lower source
    # controls, allowing outer offset clamping. No click authority is inferred.
    state.update(mode='Editing',ordinal=flow.host_lines,line=None,bottom=False)
   elif y==110:self.assertEqual(state['mode'],'Editing')
   elif y==160:
    self.assertEqual(state['mode'],'Editing')
    expected='APPROVE '+format(1 if state['stage']=='Preparation' else 2,'016x')
    self.assertEqual(state['line'],expected)
    if state['clipped']:self.assertGreaterEqual(state['coverage'],2)
    if submit_failure and state['stage']=='Pair':raise state['failure']
    state['submitted'].append((state['stage'],state['revision'],state['end'],state['ordinal']))
    state.update(mode='Writing',remaining=3,bottom=False)
    if state['stage']=='Pair':state['pair_at']=state['generation']+90
   elif y==715:
    self.assertEqual(state['mode'],'Idle');self.assertTrue(state['bottom']);state['pair_clicked']=True
   else:raise AssertionError('unexpected input edge')
  def wheel(direction,*args):
   if state['clipped'] and state['stage'] in ('Preparation','Pair') and state['coverage']<2:
    self.assertEqual(len(flow.challenges),int(state['stage']=='Pair'))
    self.assertEqual(flow.host_lines,24 if state['stage']=='Pair' else 23)
    self.assertFalse(flow.pair_navigation_submitted)
   self.assertEqual(state['mode'],'Idle');state['wheels'].append((state['generation'],direction))
   state['bottom']=direction=='down'
   if state['clipped']:state['coverage']+=1
  controller.click.side_effect=click
  def type_ascii(value):
   if type_failure and state['stage']=='Pair':raise state['failure']
   state.update(line=value)
  controller.type_ascii.side_effect=type_ascii
  controller.scroll_up.side_effect=lambda *args:wheel('up',*args)
  controller.scroll_down.side_effect=lambda *args:wheel('down',*args)
  def progress():
   state['events'].append((state['mode'],'progress'))
   if render_failure and state['stage']=='Pair' and state['mode']=='Writing':raise state['failure']
  controller.wait_render_progress.side_effect=progress
  @contextlib.contextmanager
  def observe():self.assertEqual(state['mode'],'Idle');yield object()
  controller.observe.side_effect=observe;ocr=mock.Mock();ocr.read.side_effect=lambda *args:crop()
  with mock.patch.object(m.time,'monotonic_ns',side_effect=lambda:state['clock']):
   flow=m.FullFlow(controller,fixture,Observer(),ocr)
  flow.startup_index=len(m.HOST_STARTUP);flow.commands_instruction_observed=True;flow.startup_focus_seen=True;flow._startup_ceiling=None
  # Ordinary precondition: the reviewer path was already submitted. No native
  # Pair/Final is fabricated; the real pump must consume both later approvals.
  flow.reviewer_index=int(owner[-1]);flow.host_lines=23;flow.host_occurrences.frontier=state['end']
  flow.host_occurrences.last_end=state['end'];flow.host_occurrences.last_revision=state['revision']
  return flow,controller,state,ReachedPair
 def run_model(self,flow,state,stop):
  with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:state['clock']):
   with self.assertRaises(stop):flow.run()

 def test_actual_pump_submission_reserves_original_sweep_for_late_clipped_pair(self):
  for profile in (F.C.EXTERNAL_PROFILE,F.C.SEMANTIC_PROFILE):
   for owner in ('Signer1','Signer2'):
    with self.subTest(profile=profile,owner=owner):
     flow,c,s,stop=self.model(owner,profile)
     self.run_model(flow,s,stop)
     self.assertEqual([x[0] for x in s['submitted']],['Preparation','Pair'])
     occurrence,ordinal=flow.pair_navigation_submitted[owner]
     self.assertEqual((occurrence[2],occurrence[1],ordinal),s['submitted'][-1][1:])
     self.assertEqual(flow.scrolls[('Selecting','None','idle_sweep',None)],64)
     self.assertEqual(set(s['bounds']),{301_000_000_000});self.assertTrue(flow.used(dict(phase='Selecting',subphase='None'),'ReviewV3Pair',owner))
     self.assertEqual(flow.actions,5);self.assertTrue(any(mode=='Writing' for mode,event in s['events']))
     self.assertEqual(c.type_ascii.call_count,2);c.focus.assert_not_called()
     # The former navigation policy, with real pump/capture/Submit unchanged,
     # spends its sweep before late Host input repositions the visible controls.
     before,c,old,stop=self.model(owner,profile)
     with mock.patch.object(before,'reserve_initial_pair_navigation',return_value=False):
      with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:old['clock']):
       with self.assertRaises(F.C.Rejected) as failure:before.run()
     self.assertEqual(failure.exception.code,'deadline');self.assertFalse(old['pair_clicked'])
     self.assertEqual([x[0] for x in old['submitted']],['Preparation','Pair'])
     self.assertEqual(before.scrolls[('Selecting','None','idle_sweep',None)],64)
     self.assertEqual(set(old['bounds']),{301_000_000_000})

 def test_clipped_purpose_is_not_submitted_until_complete_and_submit_error_never_promotes(self):
  flow,c,s,stop=self.model(clipped=True);self.run_model(flow,s,stop)
  self.assertGreaterEqual(s['coverage'],2);self.assertEqual(len(s['submitted']),2)
  for failure_kind in ('submit','typing','render'):
   flow,c,s,stop=self.model(submit_failure=failure_kind=='submit',type_failure=failure_kind=='typing',render_failure=failure_kind=='render')
   with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):
    with self.assertRaises(OSError) as failure:flow.run()
   self.assertIs(failure.exception,s['failure'])
   self.assertNotIn('Signer1',flow.pair_navigation_submitted)
   self.assertEqual([x[0] for x in s['submitted']],['Preparation','Pair'] if failure_kind=='render' else ['Preparation'])
   self.assertEqual(c.type_ascii.call_count,2);self.assertEqual(flow.host_lines,25)
   self.assertEqual(('Selecting','None','HostSubmit',None,25) in flow.done,failure_kind!='typing')
   self.assertIn(('Selecting','None','BeginHostLine',None,25),flow.done)
   self.assertEqual(sum(1 for call in c.click.call_args_list if call.args[1]==160),1 if failure_kind=='typing' else 2)
   self.assertEqual(flow.scrolls.get(('Selecting','None','idle_sweep',None),0),0)
  flow,c,s,stop=self.model(pair_detail='A different public purpose, not Pair.')
  with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):
   with self.assertRaises(F.C.Rejected) as failure:flow.run()
  self.assertEqual(failure.exception.code,'deadline');self.assertEqual(flow.host_lines,24)
  self.assertEqual(len(flow.challenges),1);self.assertFalse(flow.pair_navigation_submitted)
  self.assertEqual([x[0] for x in s['submitted']],['Preparation'])
  self.assertEqual(flow.host_coverage_steps,16);self.assertLessEqual(flow.host_visibility_steps,128)

 def test_exact_fresh_purpose_and_capture_context_are_required(self):
  flow,c,s,stop=self.model();detail=prompt(PAIR,9);h=dict(revision=3,nonws_end=F.H.count(detail)+100,view=dict(nonws=F.H.count(detail)))
  suffix=F.H.APPROVAL.search(detail).group(0);occurrence=(h['nonws_end']-F.H.count(suffix),h['nonws_end'],h['revision'])
  flow.host_occurrences.frontier=100
  self.assertEqual(flow.initial_pair_purpose(detail,h,occurrence,suffix),'Pair')
  for text,observation,occ in ((suffix,h,occurrence),(detail.replace('Pair this','Wrong this'),h,occurrence),
      (detail,dict(h,view=dict(nonws=F.H.count(detail)-1)),occurrence),(detail,h,(occurrence[0],occurrence[1],4)),
      (prompt(PAIR,8)+'\n'+suffix,h,occurrence)):
   self.assertIsNone(flow.initial_pair_purpose(text,observation,occ,suffix))
  self.assertIsNone(flow.initial_pair_purpose(detail,h,occurrence,suffix.replace('0000000000000009','0000000000000008')))
  flow.host_occurrences.frontier=101;self.assertIsNone(flow.initial_pair_purpose(detail,h,occurrence,suffix))
  prep=prompt(PREPARATION,9);h.update(nonws_end=F.H.count(prep)+200,view=dict(nonws=F.H.count(prep)));flow.host_occurrences.frontier=200
  suffix=F.H.APPROVAL.search(prep).group(0);occurrence=(h['nonws_end']-F.H.count(suffix),h['nonws_end'],3)
  self.assertEqual(flow.initial_pair_purpose(prep,h,occurrence,suffix),'Preparation')
  self.assertFalse(flow.pair_navigation_submitted);c.click.assert_not_called()

 def test_reservation_keeps_original_guards_counters_and_native_visible_action_path(self):
  for owner in ('Signer1','Signer2'):
   for profile in (F.C.EXTERNAL_PROFILE,F.C.SEMANTIC_PROFILE):
    flow,c,state,stop=self.model(owner,profile,visible_pair=True);self.run_model(flow,state,stop)
    self.assertFalse(flow.pair_navigation_submitted);self.assertEqual(flow.actions,1)
    self.assertFalse(state['submitted']);self.assertFalse(state['wheels']);c.type_ascii.assert_not_called()
    self.assertTrue(flow.used(dict(phase='Selecting',subphase='None'),'ReviewV3Pair',owner))
  for change in ('phase','owner','target','subphase','focus','secret','host','context','entry','pending','prepared','paired','unopened'):
   flow,c,state,stop=self.model()
   with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:state['clock']):s=flow.snapshot()
   target='Signer1'
   if change=='phase':s['phase']='V3Held'
   elif change=='owner':s['owner']='Signer1'
   elif change=='target':target='Signer2'
   elif change=='subphase':s['subphase']='SetupNeeded'
   elif change=='focus':s['focused']=False
   elif change=='secret':s['secret_input']=True
   elif change=='host':s['host_input']=True
   elif change=='context':s['host_observation']['context_valid']=False
   elif change=='entry':s['host_observation']['entry']='Writing'
   elif change=='pending':flow.pending_host=('public','inert')
   elif change=='prepared':flow.host_prepared=('inert','inert')
   elif change=='paired':flow.records.append(dict(kind='SignerMilestone',facts=dict(owner='Signer1',step='Paired')))
   else:flow.records=[]
   flow.scrolls['retained']=64;old=copy.deepcopy(flow.scrolls)
   self.assertFalse(flow.reserve_initial_pair_navigation(s,target));self.assertEqual(flow.scrolls,old);c.scroll_up.assert_not_called();c.click.assert_not_called()
  for tag in ('HostOutput','BeginHostLine'):
   flow,c,state,stop=self.model()
   with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:state['clock']):s=flow.snapshot()
   s['widgets']=[w for w in s['widgets'] if w['tag']!=tag]
   self.assertTrue(flow.reserve_initial_pair_navigation(s,'Signer1'));c.scroll_up.assert_called_once()
   self.assertEqual(flow.scrolls[('Selecting','None','seek',tag,None)],1)
   self.assertNotIn(('Selecting','None','idle_sweep',None),flow.scrolls);c.click.assert_not_called()
  flow,c,state,stop=self.model()
  with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:state['clock']):s=flow.snapshot()
  s['widgets']=[w for w in s['widgets'] if w['tag']!='BeginHostLine']
  flow.scrolls[('Selecting','None','seek','BeginHostLine',None)]=64
  with self.assertRaises(F.C.Rejected) as failure:flow.reserve_initial_pair_navigation(s,'Signer1')
  self.assertEqual(failure.exception.code,'input_widget');c.click.assert_not_called()

 def test_purposes_and_submission_order_are_bound_to_actual_producer(self):
  source=(ROOT.parent/'crates/wholepact-native-host/src/host/financial/durable_delivery_admission_v2/closed_review_v3/coordinated_export_v1.rs').read_text()
  self.assertIn('self.terminal.approve_historical("'+PREPARATION+'")',source)
  self.assertIn('host.terminal.confirm("'+PAIR+'")',source)
  self.assertLess(source.index('host.terminal.confirm("'+PAIR+'")'),source.index('CoordinatedOriginalClientV1::pair_observed'))
  terminal=(ROOT.parent/'crates/wholepact-native-host/src/terminal.rs').read_text()
  self.assertIn('write_prompt_current(&mut f, rendered.as_bytes(), bounds, held)?;\n        write_prompt_current(&mut f, prompt.as_bytes(), bounds, held)?;',terminal)
  flow=(ROOT/'ci-financial-flow.py').read_text()
  self.assertLess(flow.index("self.press(fresh,'HostSubmit',None,ordinal=self.host_lines)"),flow.index('self.pair_navigation_submitted[target]=(occurrence,self.host_lines)'))
  self.assertLess(flow.index('if selected:continue'),flow.index('if self.reserve_initial_pair_navigation(s,target):continue'))
  ui=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
  draw=ui.split('    fn draw(&mut self, ui:',1)[1].split('    fn apply_intent(',1)[0]
  self.assertLess(draw.index('self.draw_host(ui)'),draw.index('if host_entry_blocks_source(self.host_entry) { return; }'))
  self.assertLess(draw.index('if host_entry_blocks_source(self.host_entry) { return; }'),draw.index('"ReviewV3Pair"'))
  self.assertIn('matches!(entry, HostEntry::Editing(_) | HostEntry::Writing(_))',ui)
  self.assertEqual(F.C.INPUT_BUDGET_LIMITS['idle_sweep'],64);self.assertEqual(F.C.INPUT_BUDGET_LIMITS['scroll'],128)

if __name__=='__main__':unittest.main()
