"""Actual harness control flow with inert input edges, not native UI proof."""
import copy
import importlib.util
import pathlib
import sys
import time
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('financial_paired_navigation_tested',ROOT/'ci-financial-flow.py')
F=importlib.util.module_from_spec(spec);sys.modules[spec.name]=F;spec.loader.exec_module(F)

class PairedNavigationTests(unittest.TestCase):
 def frame(self,generation,tags=(),owner='Signer1',profile=None):
  rects={'SignerReviewBody':[20,80,600,380],'WitnessReviewBody':[640,80,1220,380],
   'SignerReviewAcknowledgement':[20,420,1200,440],
   'WitnessReviewAcknowledgement':[20,460,1200,480],
   'ArmSigner':[20,500,350,525],'ArmWitness':[20,540,350,565]}
  widgets=[dict(tag=tag,owner=owner,enabled=True,rect=rects[tag]) for tag in tags]
  widgets.append(dict(tag='ScrollRegion',owner=None,enabled=True,rect=[8,8,1272,792]))
  s=dict(phase='AdmissionReview',subphase='None',owner=owner,view_generation=generation,
   focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],
   host_observation=dict(revision=1,nonws_end=10,context_valid=True,entry='Idle',editor=None,view=None),
   widgets=widgets)
  if profile==F.C.SEMANTIC_PROFILE:s['host_view_id']=None
  return s
 def model(self,frames,profile=None):
  profile=profile or F.C.EXTERNAL_PROFILE
  c=mock.Mock();fixture=mock.Mock();fixture.deadline_ns=time.monotonic_ns()+120_000_000_000
  observer=mock.Mock();observer.expected_profile=profile;observer.read.return_value=[]
  queue=list(frames);bounds=[]
  def next_snapshot(deadline):
   bounds.append(deadline)
   if not queue:raise StopIteration()
   return queue.pop(0)
  observer.next_snapshot=next_snapshot
  f=F.FullFlow(c,fixture,observer,None)
  f.startup_index=len(F.HOST_STARTUP);f.commands_instruction_observed=True
  f.startup_focus_seen=True;f._startup_ceiling=None
  return f,c,bounds,queue
 def pair(self,s,generation=2):
  return [copy.deepcopy(s)|dict(view_generation=generation+i) for i in range(2)]
 def seek_key(self,tag,owner='Signer1'):
  return ('AdmissionReview','None','seek',tag,owner)
 def no_effect(self,c):
  c.scroll_up.assert_not_called();c.scroll_down.assert_not_called()
  c.click.assert_not_called();c.type_ascii.assert_not_called()

 def test_actual_flow_uses_paired_order_for_both_owners_and_profiles(self):
  for profile in (F.C.EXTERNAL_PROFILE,F.C.SEMANTIC_PROFILE):
   for owner in ('Signer1','Signer2'):
    for tag,anchor,count,direction in (
      ('ArmSigner','SignerReviewBody',0,'down'),
      ('ArmWitness','WitnessReviewAcknowledgement',0,'down'),
      ('SignerReviewBody','ArmSigner',24,'up'),
      ('WitnessReviewBody','SignerReviewAcknowledgement',24,'up')):
     with self.subTest(profile=profile,owner=owner,tag=tag):
      s=self.frame(1,(anchor,),owner,profile);f,c,bounds,_=self.model(self.pair(s),profile)
      key=self.seek_key(tag,owner);f.scrolls[key]=count;f.scrolls['retained']=17
      self.assertFalse(f.seek(s,tag,owner))
      getattr(c,'scroll_'+direction).assert_called_once()
      getattr(c,'scroll_'+('up' if direction=='down' else 'down')).assert_not_called()
      self.assertEqual(f.scrolls[key],count+1);self.assertEqual(f.scrolls['retained'],17)
      self.assertEqual(f.scrolls[('AdmissionReview','None','ScrollRegion',None,direction)],1)
      self.assertEqual(bounds,[f.fixture.deadline_ns]*2)
      self.assertFalse(f.done);self.assertEqual(f.actions,0);c.click.assert_not_called()

 def test_equal_siblings_conflicts_and_unknown_anchors_keep_bounded_fallback(self):
  cases=[('SignerReviewBody',('WitnessReviewBody',)),
   ('WitnessReviewBody',('SignerReviewBody',)),
   ('WitnessReviewAcknowledgement',('SignerReviewAcknowledgement','ArmSigner')),
   ('ArmSigner',())]
  for tag,anchors in cases:
   for count,direction in ((0,'up'),(24,'down')):
    with self.subTest(tag=tag,anchors=anchors,count=count):
     s=self.frame(1,anchors);f,c,_,_=self.model(self.pair(s));f.scrolls[self.seek_key(tag)]=count
     f.seek(s,tag,'Signer1');getattr(c,'scroll_'+direction).assert_called_once()
     self.assertEqual(f.scrolls[self.seek_key(tag)],count+1)
  s=self.frame(1,('SignerReviewBody',));fresh=self.frame(2,('ArmSigner',),owner='Signer2')
  # A wrong-owner widget is not a paired anchor, even in an otherwise valid frame.
  fresh['owner']='Signer1';f,c,_,_=self.model(self.pair(fresh,2))
  f.seek(s,'WitnessReviewBody','Signer1');c.scroll_up.assert_called_once()

 def test_only_fresh_anchors_are_used_and_newly_visible_target_returns_outer_loop(self):
  s=self.frame(1,('SignerReviewBody',));fresh=self.frame(2,('ArmSigner',))
  f,c,_,_=self.model(self.pair(fresh,2));f.scrolls[self.seek_key('SignerReviewAcknowledgement')]=24
  f.seek(s,'SignerReviewAcknowledgement','Signer1');c.scroll_up.assert_called_once()
  c.scroll_down.assert_not_called()
  fresh=self.frame(2,('SignerReviewAcknowledgement',));f,c,_,_=self.model(self.pair(fresh,2))
  self.assertFalse(f.seek(s,'SignerReviewAcknowledgement','Signer1'));self.no_effect(c)
  self.assertEqual(f.scrolls[self.seek_key('SignerReviewAcknowledgement')],1)

 def test_pre_effect_layout_deferral_preserves_counts_owed_work_and_deadline(self):
  s=self.frame(1,('SignerReviewBody',));a,b=self.pair(s);b['widgets'][0]['rect'][1]+=1
  f,c,bounds,_=self.model([a,b]);key=self.seek_key('ArmSigner');f.scrolls[key]=23
  pending=('AdmissionReview','None','paired-review-pending','Signer1','ArmSigner')
  f.scrolls[pending]=7;deadline=f.fixture.deadline_ns
  self.assertFalse(f.seek(s,'ArmSigner','Signer1'));self.no_effect(c)
  self.assertEqual(f.scrolls,{key:24,pending:7});self.assertEqual(f.actions,0);self.assertFalse(f.done)
  self.assertEqual(bounds,[deadline,deadline]);self.assertEqual(f.fixture.deadline_ns,deadline)

 def test_original_snapshot_and_input_guards_propagate(self):
  for kind in ('focus','phase','owner','secret','host','subphase','replay','duplicate','scale'):
   with self.subTest(kind=kind):
    s=self.frame(1,('SignerReviewBody',));a,b=self.pair(s)
    if kind=='focus':b['focused']=False
    elif kind=='phase':b['phase']='Reading'
    elif kind=='owner':b['owner']='Signer2'
    elif kind=='secret':b['secret_input']=True
    elif kind=='host':b['host_input']=True;b['host_observation']['entry']='Writing'
    elif kind=='subphase':b['subphase']='Review'
    elif kind=='replay':b['view_generation']=a['view_generation']
    elif kind=='duplicate':b['widgets'].append(copy.deepcopy(b['widgets'][0]))
    elif kind=='scale':b['pixels_per_point']=.75
    f,c,_,_=self.model([a,b])
    with self.assertRaises(F.C.Rejected):f.seek(s,'ArmSigner','Signer1')
    self.no_effect(c);self.assertEqual(f.scrolls[self.seek_key('ArmSigner')],1)
  s=self.frame(1,('SignerReviewBody',));f,c,bounds,_=self.model([])
  with self.assertRaises(F.C.Rejected):f.seek(s,'ArmSigner','Signer2')
  self.assertEqual(bounds,[]);self.no_effect(c)

 def test_host_currentness_and_pending_input_block_navigation(self):
  for kind in ('revision','nonws_end','invalid','closed','pending','prepared'):
   with self.subTest(kind=kind):
    s=self.frame(1,('SignerReviewBody',));fresh=copy.deepcopy(s)
    if kind in ('revision','nonws_end'):fresh['host_observation'][kind]+=1
    elif kind=='invalid':fresh['host_observation']['context_valid']=False
    elif kind=='closed':fresh['host_observation']['entry']='Closed'
    f,c,_,_=self.model(self.pair(fresh))
    if kind=='pending':f.pending_host=object()
    elif kind=='prepared':f.host_prepared=object()
    self.assertFalse(f.seek(s,'ArmSigner','Signer1'));self.no_effect(c)
    self.assertEqual(f.scrolls[self.seek_key('ArmSigner')],1)

 def test_original_seek_and_shared_wheel_caps_and_deadline_are_not_renewed(self):
  s=self.frame(1,('SignerReviewBody',));f,c,bounds,queue=self.model(self.pair(s)+self.pair(s,4))
  key=self.seek_key('ArmSigner');f.scrolls[key]=63
  f.seek(s,'ArmSigner','Signer1');self.assertEqual(f.scrolls[key],64)
  with self.assertRaises(F.C.Rejected) as error:f.seek(s,'ArmSigner','Signer1')
  self.assertEqual(error.exception.code,'input_widget');self.assertEqual(c.scroll_down.call_count,1)
  self.assertEqual(len(bounds),2)
  f,c,_,_=self.model(self.pair(s)+self.pair(s,4));key=('AdmissionReview','None','ScrollRegion',None,'down')
  f.scrolls[key]=127;f.seek(s,'ArmSigner','Signer1')
  with self.assertRaises(F.C.Rejected) as error:f.seek(s,'ArmSigner','Signer1')
  self.assertEqual(error.exception.code,'input_budget');self.assertEqual(f.scrolls[key],128)
  self.assertEqual(c.scroll_down.call_count,1)
  f,c,bounds,_=self.model([]);deadline=f.fixture.deadline_ns
  f.fixture.check.side_effect=F.C.Rejected('deadline')
  with self.assertRaises(F.C.Rejected) as error:f.seek(s,'ArmSigner','Signer1')
  self.assertEqual(error.exception.code,'deadline');self.assertEqual(f.fixture.deadline_ns,deadline)
  self.assertEqual(bounds,[]);self.no_effect(c)

 def test_actual_paired_flow_preserves_owed_body_alternation_and_one_use_arms(self):
  owner='Signer1';arms=self.frame(1,('ArmSigner','ArmWitness'))
  for w in arms['widgets']:
   if w['tag'].startswith('Arm'):w['enabled']=False
  f,c,_,queue=self.model(self.pair(arms))
  for tag in ('SignerReviewAcknowledgement','WitnessReviewAcknowledgement'):
   f.done.add(f.key(arms,tag,owner)+(None,))
  pending=('AdmissionReview','None','paired-review-pending',owner,'ArmSigner')
  turns=('AdmissionReview','None','paired-review',owner)
  f.paired_admission(arms,owner);self.assertEqual(f.scrolls[pending],0);c.scroll_up.assert_called_once()
  body=self.frame(4,('SignerReviewBody',));f.paired_admission(body,owner)
  self.assertNotIn(pending,f.scrolls);self.assertEqual(f.scrolls[turns],1)
  queue.extend(self.pair(arms,5));f.paired_admission(arms,owner)
  self.assertEqual(f.scrolls[pending],1)
  body=self.frame(7,('WitnessReviewBody',));f.paired_admission(body,owner)
  self.assertNotIn(pending,f.scrolls);self.assertEqual(f.scrolls[turns],2)
  self.assertEqual(c.scroll_down.call_args_list,[mock.call(310,230),mock.call(930,230)])
  enabled=self.frame(8,('ArmSigner','ArmWitness'));queue.extend(self.pair(enabled,9)+self.pair(enabled,11))
  f.paired_admission(enabled,owner);f.paired_admission(enabled,owner);f.paired_admission(enabled,owner)
  self.assertEqual(c.click.call_count,2);self.assertEqual(f.actions,2)
  self.assertTrue(all(f.used(enabled,tag,owner) for tag in ('ArmSigner','ArmWitness')))
  self.assertEqual(f.scrolls[turns],2)

 def test_post_effect_error_propagates_without_catching_or_repeating_input(self):
  s=self.frame(1,('SignerReviewBody',));f,c,_,_=self.model(self.pair(s))
  error=F.S.PairedLayoutChanged();c.scroll_down.side_effect=error
  with self.assertRaises(F.S.PairedLayoutChanged) as caught:f.seek(s,'ArmSigner','Signer1')
  self.assertIs(caught.exception,error);self.assertEqual(c.scroll_down.call_count,1)
  self.assertEqual(f.scrolls[('AdmissionReview','None','ScrollRegion',None,'down')],1)
  s=self.frame(1,('ArmSigner',));f,c,_,_=self.model(self.pair(s));c.click.side_effect=error
  with self.assertRaises(F.S.PairedLayoutChanged):f.press(s,'ArmSigner','Signer1',paired_layout=True)
  self.assertTrue(f.used(s,'ArmSigner','Signer1'))
  with self.assertRaises(F.C.Rejected) as replay:f.press(s,'ArmSigner','Signer1',paired_layout=True)
  self.assertEqual(replay.exception.code,'replay');self.assertEqual(c.click.call_count,1)

 def test_rank_order_is_bound_to_actual_native_columns_and_controls(self):
  self.assertEqual(F.PAIRED_REVIEW_RANK,{'SignerReviewBody':0,'WitnessReviewBody':0,
   'SignerReviewAcknowledgement':1,'WitnessReviewAcknowledgement':2,'ArmSigner':3,'ArmWitness':4})
  source=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
  draw=source.split('    fn draw_admission(',1)[1].split('    fn admit_rendezvous(',1)[0]
  self.assertIn('ui.columns(2, |columns| {',draw)
  self.assertIn('review_display_tagged(&mut columns[0], &full, visible, "SignerReviewBody")',draw)
  self.assertIn('review_display_tagged(&mut columns[1], &witness_display(p), visible, "WitnessReviewBody")',draw)
  tags=('SignerReviewBody','WitnessReviewBody','SignerReviewAcknowledgement',
   'WitnessReviewAcknowledgement','ArmSigner','ArmWitness')
  positions=[draw.index('"'+tag+'"') for tag in tags]
  self.assertEqual(positions,sorted(positions))
  self.assertLess(draw.index('        });\n        if let Some(ready)'),positions[2])
  self.assertIn('let both = paired_approved(self.paired)',draw)
  self.assertIn('both && !self.signer_arm_sent',draw);self.assertIn('both && !self.witness_arm_sent',draw)

if __name__=='__main__':unittest.main()
