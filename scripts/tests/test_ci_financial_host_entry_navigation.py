"""Actual protected pump/NativeScenario, inert geometry and input, no native grant."""
import importlib.util
import pathlib
import sys
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('host_entry_flow_tested',ROOT/'ci-financial-flow.py')
F=importlib.util.module_from_spec(spec);sys.modules[spec.name]=F;spec.loader.exec_module(F)

class HostEntryNavigationTests(unittest.TestCase):
 def model(self,owner='Signer2',profile=None,*,module=None,shape='clipped',change=None,failure=None):
  m=module or F;profile=profile or m.C.SEMANTIC_PROFILE
  state=dict(generation=0,clock=1_000_000_000,offset=0,typed=False,submitted=False,
             events=[],bounds=[],error=OSError('inert protected input failure'))
  deadline=301_000_000_000
  controller=mock.Mock();fixture=mock.Mock(deadline_ns=deadline)
  fixture.check.side_effect=lambda:m.C.require(state['clock']<deadline,'deadline')
  observer=mock.Mock(expected_profile=profile);observer.read.return_value=[]
  def next_snapshot(bound):
   state['generation']+=1;state['clock']+=1_000_000;state['bounds'].append(bound)
   m.C.require(state['clock']<bound,'deadline')
   # Actual show order: Cancel, one-line HostEditor, then HostSubmit. A
   # fully clipped lower response has no semantic widget (financial_ci::rect).
   top=-10 if shape=='partial_editor' else 790 if shape=='partial_bottom' else 764.9 if shape=='submit_sliver' else 770 if shape in ('clipped','never','bottom_clamped') else 730
   top+=state['offset'];editor=[10,max(0,top),250,min(800,top+20)]
   submit=[10,top+35,250,top+55]
   widgets=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,800])]
   if editor[3]>0 and editor[1]<800:widgets.append(dict(tag='HostEditor',owner=None,enabled=shape!='editor_disabled',rect=editor))
   if submit[1]<800 and shape!='never' and not(change=='after_type_clip' and state['typed']):
    widgets.append(dict(tag='HostSubmit',owner=None,enabled=shape!='disabled',rect=[submit[0],submit[1],submit[2],min(800,submit[3])]))
   if shape=='unreachable_editor':widgets=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,10]),
       dict(tag='HostEditor',owner=None,enabled=True,rect=[10,0,250,10])]
   s=dict(phase='V3Receiving',subphase='None',owner=owner,view_generation=state['generation'],focused=True,
          secret_input=False,host_input=True,pixels_per_point=1,viewport=[1280,800],widgets=widgets,
          host_observation=dict(revision=9,nonws_end=100,context_valid=True,entry='Editing',
              editor=dict(ordinal=28,revision=9),view=None))
   if profile==m.C.SEMANTIC_PROFILE:s['host_view_id']=None
   if state['generation']>=2 and change not in (None,'after_type_clip'):
    if change=='phase':s['phase']='ReturnReading'
    elif change=='owner':s['owner']='Signer1' if owner=='Signer2' else 'Signer2'
    elif change=='subphase':s['subphase']='SetupNeeded'
    elif change=='focus':s['focused']=False
    elif change=='secret':s['secret_input']=True
    elif change=='host':s['host_input']=False
    elif change=='revision':s['host_observation']['revision']=10;s['host_observation']['editor']['revision']=10
    elif change=='end':s['host_observation']['nonws_end']=101
    elif change=='ordinal':s['host_observation']['editor']['ordinal']=29
    elif change=='context':s['host_observation']['context_valid']=False
   return s
  observer.next_snapshot.side_effect=next_snapshot
  def wheel(direction,x,y):
   self.assertFalse(state['typed']);self.assertFalse(state['submitted']);state['events'].append(direction)
   # The clear rounded outer point is not on either protected input control.
   self.assertGreater(x,250);self.assertTrue(0<y<800)
   if shape not in ('never','unreachable_editor'):state['offset']+=-60 if direction=='down' else 60
   if shape=='bottom_clamped':state['offset']=max(-25,state['offset'])
  controller.scroll_down.side_effect=lambda x,y:wheel('down',x,y)
  controller.scroll_up.side_effect=lambda x,y:wheel('up',x,y)
  def click(x,y):
   if not state['typed']:
    state['events'].append('editor_click')
    if failure=='editor_click':raise state['error']
   else:
    state['events'].append('submit_click')
    if failure=='submit_click':raise state['error']
    state['submitted']=True
  controller.click.side_effect=click
  def type_ascii(value):
   state['events'].append('type');self.assertEqual(value,'APPROVE 0123456789abcdef')
   if failure=='typing':raise state['error']
   state['typed']=True
  controller.type_ascii.side_effect=type_ascii
  def progress():
   if failure=='submit_progress' and state['submitted']:raise state['error']
  controller.wait_render_progress.side_effect=progress
  controller.observe.side_effect=AssertionError('no protected capture')
  flow=m.FullFlow(controller,fixture,observer,mock.Mock())
  flow.startup_index=13;flow.commands_instruction_observed=True;flow._startup_ceiling=None;flow.host_lines=28
  # Ordinary current-editor precondition; no native Final/custody is fabricated.
  flow.pending_host=('public','APPROVE 0123456789abcdef');flow.pending_occurrence=(0,100,9)
  flow.done.add(('V3Receiving','None','BeginHostLine',None,28))
  return flow,controller,state
 def run_pending(self,flow,state):
  with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:state['clock']):
   while flow.pending_host is not None:flow.pump_host(flow.snapshot())

 def test_missing_or_partial_controls_are_positioned_before_one_type_and_submit(self):
  for profile in (F.C.EXTERNAL_PROFILE,F.C.SEMANTIC_PROFILE):
   for owner in ('Signer1','Signer2'):
    for shape,direction in (('clipped','down'),('partial_editor','up'),('partial_bottom','down'),('submit_sliver','down'),('bottom_clamped','down'),('visible',None)):
     with self.subTest(profile=profile,owner=owner,shape=shape):
      flow,c,state=self.model(owner,profile,shape=shape);self.run_pending(flow,state)
      expected=([direction] if direction else [])+['editor_click','type','submit_click']
      self.assertEqual(state['events'],expected);self.assertEqual(c.type_ascii.call_count,1)
      self.assertEqual(flow.actions,1);self.assertEqual(set(state['bounds']),{301_000_000_000})
      if shape=='bottom_clamped':self.assertEqual(770+state['offset']+55,800)
      self.assertIn(('V3Receiving','None','HostSubmit',None,28),flow.done)
      c.observe.assert_not_called();flow.ocr.read.assert_not_called();c.focus.assert_not_called()

 def test_disabled_and_changed_currentness_remain_terminal_before_input(self):
  for shape in ('disabled','editor_disabled'):
   flow,c,state=self.model(shape=shape)
   with self.assertRaises(F.C.Rejected) as e:self.run_pending(flow,state)
   self.assertEqual(e.exception.code,'input_disabled');self.assertFalse(state['events'])
  for change in ('phase','owner','subphase','focus','secret','host','revision','end','ordinal','context'):
   with self.subTest(change=change):
    flow,c,state=self.model(change=change)
    with self.assertRaises(F.C.Rejected):self.run_pending(flow,state)
    self.assertFalse(state['events']);self.assertIsNotNone(flow.pending_host)
    c.type_ascii.assert_not_called();c.observe.assert_not_called()

 def test_original_navigation_caps_deadline_and_rounded_clear_point_are_retained(self):
  flow,c,state=self.model(shape='never')
  with self.assertRaises(F.C.Rejected) as e:self.run_pending(flow,state)
  self.assertEqual(e.exception.code,'input_widget');self.assertEqual(state['events'],['down']*64)
  c.type_ascii.assert_not_called();self.assertEqual(set(state['bounds']),{301_000_000_000})
  flow,c,state=self.model(shape='unreachable_editor')
  with self.assertRaises(F.C.Rejected) as e:self.run_pending(flow,state)
  self.assertEqual(e.exception.code,'input_widget');self.assertEqual(state['events'],['up']*24+['down']*40)
  c.type_ascii.assert_not_called();self.assertIsNotNone(flow.pending_host)
  flow,c,state=self.model();key=('V3Receiving','None','ScrollRegion',None,'down');flow.scrolls[key]=128
  with self.assertRaises(F.C.Rejected) as e:self.run_pending(flow,state)
  self.assertEqual(e.exception.code,'input_budget');self.assertEqual(flow.scrolls[key],128);self.assertFalse(state['events'])
  flow,c,state=self.model();state['clock']=301_000_000_000
  with self.assertRaises(F.C.Rejected) as e:self.run_pending(flow,state)
  self.assertEqual(e.exception.code,'deadline');self.assertFalse(state['events'])
  flow,c,state=self.model()
  with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:state['clock']):s=flow.snapshot()
  s['pixels_per_point']=0.5
  # A logical point clear of this editor rounds onto its edge; no wheel allowed.
  s['widgets']=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,100.8,100]),
                dict(tag='HostEditor',owner=None,enabled=True,rect=[0,0,96.1,100])]
  with self.assertRaises(F.C.Rejected) as e:flow.scroll(s,'ScrollRegion',None,'down')
  self.assertEqual(e.exception.code,'input_widget');self.assertFalse(state['events'])

 def test_no_retry_after_typing_or_possible_submit_and_no_latch_reset(self):
  for failure in ('editor_click','typing','submit_click','submit_progress'):
   flow,c,state=self.model(shape='visible',failure=failure)
   with self.assertRaises(OSError) as e:self.run_pending(flow,state)
   self.assertIs(e.exception,state['error']);self.assertIsNotNone(flow.pending_host)
   self.assertLessEqual(c.type_ascii.call_count,1)
   self.assertEqual(state['events'].count('submit_click'),int(failure.startswith('submit_')))
   self.assertEqual(('V3Receiving','None','HostSubmit',None,28) in flow.done,failure.startswith('submit_'))
   c.scroll_down.assert_not_called();c.observe.assert_not_called()
  flow,c,state=self.model(shape='visible',change='after_type_clip')
  with self.assertRaises(F.C.Rejected) as e:self.run_pending(flow,state)
  self.assertEqual(e.exception.code,'input_disabled');self.assertEqual(state['events'],['editor_click','type'])
  self.assertEqual(c.type_ascii.call_count,1);self.assertIsNotNone(flow.pending_host)
  flow,c,state=self.model(shape='visible');flow.done.add(('V3Receiving','None','HostSubmit',None,28))
  with self.assertRaises(F.C.Rejected) as e:self.run_pending(flow,state)
  self.assertEqual(e.exception.code,'replay');self.assertEqual(state['events'].count('submit_click'),0)

 def test_route_is_bound_to_actual_native_editor_order_clipping_and_existing_submit(self):
  native=(ROOT.parent/'crates/wholepact-financial-coordinator/src/host_line_input.rs').read_text()
  show=native.split('pub(super) fn show(',1)[1].split('pub(super) fn finish_frame(',1)[0]
  self.assertLess(show.index('egui::TextEdit::singleline'),show.index('"HostEditor"'))
  self.assertLess(show.index('"HostEditor"'),show.index('ui\n            .add_enabled(eligible, egui::Button::new("Send this exact Host line"))'))
  self.assertLess(show.index('"Send this exact Host line"'),show.index('"HostSubmit"'))
  observer=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_ci.rs').read_text()
  rect=observer.split('pub(super) fn rect(',1)[1].split('/// Called only after real layout.',1)[0]
  self.assertIn('let r = actual.intersect(ui.clip_rect()).intersect(bounds);',rect)
  self.assertIn('if !r.is_positive() { return; }',rect)
  ui=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
  draw=ui.split('    fn draw(&mut self, ui:',1)[1].split('    fn check_current(',1)[0]
  self.assertLess(draw.index('self.draw_host(ui)'),draw.index('if host_entry_blocks_source(self.host_entry) { return; }'))
  host=ui.split('    fn draw_host(',1)[1].split('    fn ',1)[0]
  self.assertIn('input.show(ui, ordinal',host)
  flow=(ROOT/'ci-financial-flow.py').read_text();pump=flow.split('    def pump_host(',1)[1].split('    def cache_input_checkpoint(',1)[0]
  self.assertLess(pump.index('self.host_entry_controls_visible(s,occurrence)'),pump.index("self.host_action='TypingRequested'"))
  self.assertLess(pump.index("self.host_action='TypingReturned'"),pump.index("self.press(fresh,'HostSubmit',None,ordinal=self.host_lines)"))
  self.assertEqual(pump.count("self.press(fresh,'HostSubmit',None,ordinal=self.host_lines)"),1)
  self.assertEqual(F.C.INPUT_BUDGET_LIMITS['scroll'],128)
  scenario=(ROOT/'ci-financial-scenario.py').read_text()
  point=scenario.split('    def point(',1)[1].split('    def click(',1)[0]
  self.assertIn('return int((x0+x1)*scale/2),int((y0+y1)*scale/2)',point)

if __name__=='__main__':unittest.main()
