"""Actual FullFlow/NativeScenario navigation; inert clipping, no Host authority."""
import importlib.util
import pathlib
import sys
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('waiting_host_flow_tested',ROOT/'ci-financial-flow.py')
F=importlib.util.module_from_spec(spec);sys.modules[spec.name]=F;spec.loader.exec_module(F)

class CaptureReached(Exception):pass
class ActionReached(Exception):pass

class WaitingHostOrderTests(unittest.TestCase):
 def model(self,owner='Signer1',profile=None,phase='V3Receiving',target='BeginHostLine',*,seed=0,reveal_after=1,change=None,sibling='valid',module=None):
  m=module or F;profile=profile or m.C.SEMANTIC_PROFILE
  state=dict(frame=0,clock=1_000_000_000,moved=False,events=[],bounds=[],error=OSError('inert wheel failure'))
  deadline=301_000_000_000;controller=mock.Mock();fixture=mock.Mock(deadline_ns=deadline)
  fixture.check.side_effect=lambda:m.C.require(state['clock']<fixture.deadline_ns,'deadline')
  observer=mock.Mock(expected_profile=profile);observer.read.return_value=[]
  def next_snapshot(bound):
   state['frame']+=1;state['clock']+=1_000_000;state['bounds'].append(bound)
   m.C.require(state['clock']<bound,'deadline')
   if state['frame']>400:raise AssertionError('model observation bound')
   ws=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,800])]
   # Exact native order, with positive intersection rectangles only. Scroll
   # input changes this inert viewport; no egui/native authority is simulated.
   if state['moved']:
    ws += [dict(tag='HostOutput',owner=None,enabled=True,rect=[10,400,600,640]),
           dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,650,200,680])]
    view=dict(rect=[10,600,600,620],nonws=110,rows=1)
   elif target=='BeginHostLine':
    ws.append(dict(tag='HostOutput',owner=None,enabled=True,rect=[10,600,600,790]));view=dict(rect=[10,700,600,720],nonws=110,rows=1)
   else:
    ws.append(dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,10,200,40]));view=None
   if not state['moved'] and sibling!='valid':
    if sibling=='absent':ws=ws[:1];view=None
    elif sibling=='wrong_owner':ws[-1]['owner']=owner;view=None
    elif sibling=='disabled':ws[-1]['enabled']=False;view=None
    elif sibling=='invalid_rect':ws[-1]['rect'][3]=ws[-1]['rect'][1]
   s=dict(phase=phase,subphase='None',owner=owner,view_generation=state['frame'],focused=True,
          secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=ws,
          host_observation=dict(revision=18,nonws_end=110,context_valid=True,entry='Idle',editor=None,view=view))
   if profile==m.C.SEMANTIC_PROFILE:s['host_view_id']=1 if view else None
   if change is not None and state['frame']>=2:change(s,state)
   return s
  observer.next_snapshot.side_effect=next_snapshot
  direction='down' if target=='BeginHostLine' else 'up'
  def wheel(d,*point):
   state['events'].append(d)
   if reveal_after is not None and state['events'].count(direction)>=reveal_after:state['moved']=True
  controller.scroll_up.side_effect=lambda *p:wheel('up',*p)
  controller.scroll_down.side_effect=lambda *p:wheel('down',*p)
  flow=m.FullFlow(controller,fixture,observer,None)
  flow.startup_index=13;flow.startup_focus_seen=True;flow.commands_instruction_observed=True;flow._startup_ceiling=None;flow.host_lines=17
  flow.host_occurrences.frontier=100;flow.host_occurrences.last_end=100;flow.host_occurrences.last_revision=17
  flow.last_phase=(phase,'None',owner);flow.scrolls[(phase,'None','seek',target,None)]=seed
  # Stop BEFORE capture/approval. Actual pump, stable-frame and snapshot guards
  # execute; no prompt or permission is invented by the geometry model.
  flow.native.capture_host=mock.Mock(side_effect=CaptureReached())
  return flow,controller,state
 def run_model(self,flow,state):
  with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:state['clock']):flow.run()
 def initial(self,flow,state):
  with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:state['clock']):return flow.snapshot()

 def test_both_native_waiting_routes_follow_visible_sibling_in_each_direction(self):
  for profile in (F.C.PROFILE,F.C.EXTERNAL_PROFILE,F.C.SEMANTIC_PROFILE):
   for owner in ('Signer1','Signer2'):
    for phase in ('V3Receiving','ReturnReading'):
     for target,seed in (('BeginHostLine',0),('HostOutput',0),('HostOutput',24)):
      with self.subTest(profile=profile,owner=owner,phase=phase,target=target,seed=seed):
       f,c,s=self.model(owner,profile,phase,target,seed=seed,reveal_after=2)
       with self.assertRaises(CaptureReached):self.run_model(f,s)
       direction='down' if target=='BeginHostLine' else 'up'
       self.assertEqual(s['events'],[direction]*2);self.assertEqual(s['frame'],7)
       self.assertEqual(f.scrolls[(phase,'None','seek',target,None)],seed+2)
       self.assertEqual(set(s['bounds']),{301_000_000_000});self.assertEqual(f.host_lines,17)
       self.assertIsNone(f.pending_host);self.assertIsNone(f.host_prepared)
       c.click.assert_not_called();c.type_ascii.assert_not_called();f.native.capture_host.assert_called_once()

 def test_only_current_enabled_ownerless_sibling_changes_original_fallback(self):
  for sibling in ('absent','wrong_owner','disabled'):
   f,c,s=self.model(sibling=sibling);initial=self.initial(f,s)
   with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):self.assertTrue(f.pump_host(initial))
   self.assertEqual(s['events'],['up']);f.native.capture_host.assert_not_called();c.click.assert_not_called()
  f,c,s=self.model(sibling='invalid_rect')
  with self.assertRaises(F.C.Rejected) as e:self.initial(f,s)
  self.assertEqual(e.exception.code,'snapshot');self.assertFalse(s['events'])
  # Disabled Begin was already an explicit no-navigation condition, not an anchor.
  f,c,s=self.model(target='HostOutput',sibling='disabled');initial=self.initial(f,s)
  with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):self.assertFalse(f.pump_host(initial))
  self.assertFalse(s['events'])
  # An already visible pair of controls reaches the original capture route.
  f,c,s=self.model();s['moved']=True
  with self.assertRaises(CaptureReached):self.run_model(f,s)
  self.assertFalse(s['events']);self.assertEqual(s['frame'],1)

 def test_changed_source_context_protection_and_phase_never_navigate(self):
  def change(kind):
   def apply(row,state):
    h=row['host_observation']
    if kind=='owner':row['owner']='Signer2'
    elif kind=='phase':row['phase']='ReturnReading'
    elif kind=='subphase':row['subphase']='SetupNeeded'
    elif kind=='focus':row['focused']=False
    elif kind=='secret':row['secret_input']=True
    elif kind=='host':row['host_input']=True
    elif kind=='revision':h['revision']+=1
    elif kind=='end':h['nonws_end']+=1
    elif kind=='invalid':h['context_valid']=False
    elif kind=='replay':row['view_generation']=1
    elif kind=='geometry' and state['frame']==3:row['widgets'][-1]['rect'][0]+=1
    if kind in ('focus','secret','host','invalid'):
     h['view']=None
     if 'host_view_id' in row:row['host_view_id']=None
   return apply
  for kind in ('owner','phase','subphase','focus','secret','host','revision','end','invalid','replay','geometry'):
   with self.subTest(kind=kind):
    f,c,s=self.model(change=change(kind));initial=self.initial(f,s)
    try:
     with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):f.pump_host(initial)
    except F.C.Rejected:pass
    self.assertFalse(s['events']);f.native.capture_host.assert_not_called();c.click.assert_not_called()
  for blocked in ('pending','prepared','consumed'):
   f,c,s=self.model();initial=self.initial(f,s)
   if blocked=='pending':f.pending_host=('public','unused')
   elif blocked=='prepared':f.host_prepared=('unused',)
   else:f.host_occurrences.frontier=110
   with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):self.assertTrue(f.seek_waiting_host_control(initial,'BeginHostLine'))
   self.assertFalse(s['events'])

 def test_original_seek_scroll_deadline_and_effect_failure_bounds_are_unchanged(self):
  for seed,expected in ((63,['down']),(64,[])):
   f,c,s=self.model(seed=seed,reveal_after=None)
   with self.assertRaises(F.C.Rejected) as e:self.run_model(f,s)
   self.assertEqual(e.exception.code,'input_widget');self.assertEqual(s['events'],expected)
   self.assertEqual(f.scrolls[('V3Receiving','None','seek','BeginHostLine',None)],65)
   c.click.assert_not_called();f.native.capture_host.assert_not_called()
  f,c,s=self.model();f.scrolls[('V3Receiving','None','ScrollRegion',None,'down')]=128
  with self.assertRaises(F.C.Rejected) as e:self.run_model(f,s)
  self.assertEqual(e.exception.code,'input_budget');self.assertFalse(s['events'])
  f,c,s=self.model();f.fixture.deadline_ns=s['clock']
  with self.assertRaises(F.C.Rejected) as e:self.run_model(f,s)
  self.assertEqual(e.exception.code,'deadline');self.assertFalse(s['events'])
  f,c,s=self.model();c.scroll_down.side_effect=s['error']
  with self.assertRaises(OSError) as e:self.run_model(f,s)
  self.assertIs(e.exception,s['error']);self.assertEqual(c.scroll_down.call_count,1)
  self.assertEqual(f.scrolls[('V3Receiving','None','seek','BeginHostLine',None)],1)
  self.assertEqual(f.scrolls[('V3Receiving','None','ScrollRegion',None,'down')],1)
  f.native.capture_host.assert_not_called();c.click.assert_not_called()

 def ordered_model(self,case,owner='Signer1',profile=None,*,change=None):
  profile=profile or F.C.SEMANTIC_PROFILE
  phase='Selecting' if case=='selecting' else 'Configuring';active=None if case=='selecting' else owner
  f,c,state=self.model(owner,profile,phase);state['done']=False
  records=[dict(kind='SignerMilestone',facts=dict(owner=owner,step='Paired'))]
  if owner=='Signer2':records.append(dict(kind='SignerMilestone',facts=dict(owner='Signer1',step='SigningRetired')))
  f.observer.read.return_value=records;f.records=records
  f.fixture.source_path.return_value='/tmp/never-created-order-test-selector'
  f.fixture.form.return_value={tag[6:]:'a' for tag in F.WITNESS_FIELDS}
  f.host_occurrences.frontier=110
  if case=='form':f.filled={(phase,tag,owner) for tag in F.WITNESS_FIELDS}
  def next_snapshot(bound):
   if state['done']:raise ActionReached()
   state['frame']+=1;state['clock']+=1_000_000;state['bounds'].append(bound)
   F.C.require(state['clock']<bound,'deadline')
   ws=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,800])]
   if case=='form':ws.append(dict(tag=F.WITNESS_FIELDS[-1],owner=owner,enabled=True,rect=[10,650,900,670]))
   else:ws.extend([dict(tag='HostOutput',owner=None,enabled=True,rect=[10,400,600,640]),
                   dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,650,200,680])])
   if state['moved']:ws.append(dict(tag='Begin' if case=='form' else 'ReviewV3Manifest',owner=owner,enabled=True,rect=[10,750,200,780]))
   row=dict(phase=phase,subphase='None',owner=active,view_generation=state['frame'],focused=True,
       secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=ws,
       host_observation=dict(revision=18,nonws_end=110,context_valid=True,entry='Idle',editor=None,view=None))
   if profile==F.C.SEMANTIC_PROFILE:row['host_view_id']=None
   if change and state['frame']>=2:change(row,state)
   return row
  f.observer.next_snapshot.side_effect=next_snapshot
  def wheel(direction,*point):state['events'].append(direction);state['moved']|=direction=='down'
  c.scroll_up.side_effect=lambda *p:wheel('up',*p);c.scroll_down.side_effect=lambda *p:wheel('down',*p)
  c.click.side_effect=lambda *p:state.update(done=True)
  return f,c,state

 def test_post_pair_selection_and_completed_form_use_native_order_before_real_action(self):
  for profile in (F.C.EXTERNAL_PROFILE,F.C.SEMANTIC_PROFILE):
   for owner in ('Signer1','Signer2'):
    for case in ('selecting','form'):
     with self.subTest(profile=profile,owner=owner,case=case):
      f,c,s=self.ordered_model(case,owner,profile)
      with self.assertRaises(ActionReached):self.run_model(f,s)
      self.assertEqual(s['events'],['down']);self.assertEqual(s['frame'],6);self.assertEqual(f.actions,1)
      c.click.assert_called_once_with(105,765);c.type_ascii.assert_not_called();f.native.capture_host.assert_not_called()
      self.assertEqual(set(s['bounds']),{301_000_000_000});self.assertEqual(f.host_lines,17)
      key=('Selecting','None','idle_sweep',None) if case=='selecting' else ('Configuring','None','seek','Begin',owner)
      self.assertEqual(f.scrolls[key],1)

 def test_new_direction_routes_preserve_fallback_and_reject_stale_metadata(self):
  for case in ('selecting','form'):
   for missing in ('prerequisite','disabled','owner'):
    f,c,s=self.ordered_model(case);initial=self.initial(f,s)
    if missing=='prerequisite':
     if case=='form':f.filled.remove(('Configuring',F.WITNESS_FIELDS[0],'Signer1'))
     else:f.records=[];f.observer.read.return_value=[]
    else:
     original=f.observer.next_snapshot.side_effect
     def changed(bound):
      row=original(bound)
      for w in row['widgets']:
       if w['tag']==(F.WITNESS_FIELDS[-1] if case=='form' else 'BeginHostLine'):
        if missing=='disabled':w['enabled']=False
        else:w['owner']='Signer2'
      return row
     f.observer.next_snapshot.side_effect=changed
     initial=changed(301_000_000_000)
    with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):
     if case=='form':f.seek(initial,'Begin','Signer1')
     else:f.idle_scan(initial)
    self.assertEqual(s['events'],['up']);c.click.assert_not_called()
   for kind in ('revision','end','writing','owner','subphase','focus','protected','geometry'):
    def change(row,state):
     if kind=='revision':row['host_observation']['revision']+=1
     elif kind=='end':row['host_observation']['nonws_end']+=1
     elif kind=='writing':row['host_observation']['entry']='Writing';row['host_input']=True
     elif kind=='owner':row['owner']='Signer2'
     elif kind=='subphase':row['subphase']='SetupNeeded'
     elif kind=='focus':row['focused']=False
     elif kind=='protected':row['secret_input']=True
     elif kind=='geometry' and state['frame']==3:row['widgets'][-1]['rect'][0]+=1
    f,c,s=self.ordered_model(case,change=change);initial=self.initial(f,s)
    try:
     with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):
      if case=='form':f.seek(initial,'Begin','Signer1')
      else:f.idle_scan(initial)
    except F.C.Rejected:pass
    self.assertFalse(s['events']);c.click.assert_not_called();f.native.capture_host.assert_not_called()
   for blocked in ('pending','prepared'):
    f,c,s=self.ordered_model(case);initial=self.initial(f,s)
    if blocked=='pending':f.pending_host=('public','unused')
    else:f.host_prepared=('unused',)
    with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']):
     if case=='form':f.seek(initial,'Begin','Signer1')
     else:f.idle_scan(initial)
    self.assertFalse(s['events']);c.click.assert_not_called()
   f,c,s=self.ordered_model(case);initial=self.initial(f,s)
   key=('Selecting','None','idle_sweep',None) if case=='selecting' else ('Configuring','None','seek','Begin','Signer1')
   f.scrolls[key]=64
   with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:s['clock']),self.assertRaises(F.C.Rejected):
    if case=='form':f.seek(initial,'Begin','Signer1')
    else:f.idle_scan(initial)
   self.assertFalse(s['events']);c.click.assert_not_called()

 def test_route_is_bound_to_actual_native_order_and_original_guarded_pump(self):
  source=(ROOT/'ci-financial-flow.py').read_text()
  body=source.split('    def seek_waiting_host_control(',1)[1].split('    def host_entry_controls_visible(',1)[0]
  for token in ("('V3Receiving','ReturnReading')","('HostOutput','BeginHostLine')","s['subphase']=='None'",
                "s['owner'] in ('Signer1','Signer2')","self.native.stable(s['phase'],s['owner'])",
                "(h['revision'],h['nonws_end'])!=(old['revision'],old['nonws_end'])",
                "h['nonws_end']<=self.host_occurrences.frontier","count<64","else:self.seek(latest,tag,None)"):
   self.assertIn(token,body)
  self.assertNotIn('capture_host(',body);self.assertNotIn('.press(',body)
  ui=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
  draw=ui.split('    fn draw_host(',1)[1].split('    fn ',1)[0]
  self.assertLess(draw.index('"HostOutput"'),draw.index('"BeginHostLine"'))
  ci=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_ci.rs').read_text()
  self.assertIn('actual.intersect(ui.clip_rect()).intersect(bounds)',ci);self.assertIn('!r.is_positive()',ci)
  draw_ui=ui.split('if host_phase_allows_input(self.phase) || self.terminal() { self.draw_host(ui); }',1)[1]
  self.assertLess(draw_ui.index('if host_entry_blocks_source(self.host_entry) { return; }'),draw_ui.index('"ReviewV3Manifest"'))
  for tag in (*F.SELECT,'PrepareCompletedPair','ResumeFinancial'):self.assertIn('"'+tag+'"',draw_ui)
  fields=ui.split('fn draw_selectors(',1)[1].split('fn history_inputs(',1)[0]
  self.assertIn('['+', '.join('"'+tag+'"' for tag in F.WITNESS_FIELDS)+'][ordinal]',fields)
  self.assertEqual(len(F.WITNESS_FIELDS),11);self.assertEqual(F.WITNESS_FIELDS[-1],'Field:TrustedClientRoot')
  form=ui.split('Phase::Configuring => {',1)[1].split('Phase::',1)[0]
  self.assertLess(form.index('draw_selectors('),form.index('"Begin"'))
  self.assertIn("all((s['phase'],field,owner) in self.filled for field in WITNESS_FIELDS)",source)
  self.assertIn("self.milestone(self.current_owner(),'Paired')",source)

  scenario=(ROOT/'ci-financial-scenario.py').read_text().split('    def stable(',1)[1].split('    @staticmethod',1)[0]
  self.assertIn("s['owner']==owner",scenario);self.assertIn('shape(first)==shape(second)',scenario)

if __name__=='__main__':unittest.main()
