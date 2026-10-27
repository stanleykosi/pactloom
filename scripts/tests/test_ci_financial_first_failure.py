"""First validated failure-batch diagnostics; no native process or input."""
import copy
import json
import pathlib
import tempfile
import unittest
from unittest import mock
import test_ci_financial_observer as T

O=T.O
C=O.C

class FirstFailureTests(unittest.TestCase):
 def fixture(self,rows=None,deadline=1_000_000_000):
  td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
  directory=pathlib.Path(td.name)
  o=O.ObserverFiles(directory,deadline,C.SEMANTIC_PROFILE)
  if rows is not None:self.write(directory,rows)
  return directory,o
 def row(self,role='Coordinator',kind='Failure',sequence=2,elapsed=2,facts=None):
  return dict(schema=1,profile=C.SEMANTIC_PROFILE,role=role,kind=kind,sequence=sequence,
              elapsed_ns=elapsed,facts=dict(code='source_failure') if facts is None else facts)
 def birth(self,role='Coordinator',pid=100):
  parent=None if role=='Coordinator' else C.PARENTS[role]
  return self.row(role,'Birth',1,1,dict(pid=pid,parent_pid=99 if parent is None else 101 if parent=='Host' else 100,parent_role=parent))
 def write(self,directory,rows,pid=100):
  path=directory/(str(pid)+'.jsonl');path.write_bytes(b''.join(json.dumps(r).encode()+b'\n' for r in rows));path.chmod(0o600)
  return path
 def read(self,o,started=10,finished=11,**kwargs):
  with mock.patch.object(O.time,'monotonic_ns',side_effect=[started,finished]) as clock:
   result=o.read(**kwargs)
  self.assertEqual(clock.call_count,2)
  return result
 def value(self,events):
  return dict(version=1,site='NextSnapshotFailureRecords',first_observed=dict(
   availability='Observed',read_index=1,since_first_successful_read_ns=0,events=events))
 def event(self,row):
  return {k:copy.deepcopy(row[k]) for k in ('role','kind','sequence','facts')}|dict(actor_elapsed_ns=row['elapsed_ns'])
 def test_empty_then_first_successful_failure_preserves_finite_reason_and_relative_offset(self):
  directory,o=self.fixture([self.birth()]);self.read(o)
  self.assertEqual(o.first_failure_observation(),C.unavailable_first_failure_observation())
  row=self.row();self.write(directory,[self.birth(),row]);self.read(o,25,26)
  expected=self.value([self.event(row)])['first_observed'];expected.update(read_index=2,since_first_successful_read_ns=15)
  self.assertEqual(o.first_failure_observation(),expected)
  result=o.first_failure_observation();result['events'][0]['facts']['code']='process'
  self.assertEqual(o.first_failure_observation(),expected)
 def test_first_batch_keeps_per_role_min_sequence_canonical_role_order_not_elapsed_sort(self):
  directory,o=self.fixture([self.birth(),self.row(sequence=2,elapsed=900),self.row(sequence=3,elapsed=950,facts={'code':'process'})])
  signer=self.row('Signer1',elapsed=2)
  self.write(directory,[self.birth('Signer1',2),signer],2)
  self.read(o)
  events=o.first_failure_observation()['events']
  self.assertEqual([v['role'] for v in events],['Coordinator','Signer1'])
  self.assertEqual([v['actor_elapsed_ns'] for v in events],[900,2])
  self.assertEqual(events[0]['facts'],{'code':'source_failure'})
  self.assertEqual(events[0]['sequence'],2)
 def test_frozen_first_batch_does_not_add_later_actor_or_replace_later_native_facts(self):
  first=T.NativeFailureBoundaryTests().record()
  directory,o=self.fixture([self.birth(),first]);self.read(o);expected=o.first_failure_observation()
  later=copy.deepcopy(first);later['sequence']=3;later['elapsed_ns']=3;later['facts']['driver']='WorkErrorUnclassified'
  self.write(directory,[self.birth(),first,later]);self.write(directory,[self.birth('Signer1',102),self.row('Signer1')],102)
  self.read(o,30,31)
  self.assertEqual(o.first_failure_observation(),expected)
  self.assertEqual(o.failure_diagnostics()['native']['driver'],'WorkErrorUnclassified')
 def test_actual_bounded_drain_enriches_last_cache_but_not_first_batch(self):
  first=T.NativeFailureBoundaryTests().record()
  directory,o=self.fixture([self.birth(),first],deadline=40_000_000)
  clock=[10];sleeps=[0]
  def sleep(delay):
   clock[0]+=max(1,int(delay*1_000_000_000));sleeps[0]+=1
   if sleeps[0]==1:
    f=dict(version=1,driver={'stage':'OriginalActors','class':'IoPermissionDenied'},listener=None,origin=None)
    self.write(directory,[self.birth('Signer1',102),self.row('Signer1','ActorFailureBoundary',facts=f)],102)
  with mock.patch.object(O.time,'monotonic_ns',side_effect=lambda:clock[0]),mock.patch.object(O.time,'sleep',side_effect=sleep):
   with self.assertRaises(C.Rejected) as raised:o.next_snapshot(o.deadline_ns)
  self.assertEqual(raised.exception.code,'observer_failure')
  self.assertEqual(raised.exception.observer_failure_site,'NextSnapshotFailureRecords')
  self.assertEqual([v['role'] for v in o.first_failure_observation()['events']],['Coordinator'])
  self.assertIsNotNone(o.failure_diagnostics()['actor']['actors']['Signer1']['failure'])
  self.assertEqual(o._failure_drain_deadline,o.deadline_ns)
  with mock.patch.object(o,'read',side_effect=AssertionError('must not retry')):
   with self.assertRaises(C.Rejected) as raised:o.next_snapshot(o.deadline_ns+1)
  self.assertEqual(raised.exception.observer_failure_site,'NextSnapshotLatched')
 def test_late_read_does_not_commit_candidate_epoch_or_read_counter(self):
  directory,o=self.fixture([self.birth(),self.row()],deadline=100)
  with mock.patch.object(O.time,'monotonic_ns',side_effect=[10,100]):
   with self.assertRaises(C.Rejected) as raised:o.read()
  self.assertEqual(raised.exception.code,'deadline');self.assertIsNone(o._first_failure)
  self.assertIsNone(o._first_successful_read_ns);self.assertEqual(o._successful_reads,0)
  self.read(o,20,21)
  self.assertEqual(o.first_failure_observation()['read_index'],1)
  self.assertEqual(o.first_failure_observation()['since_first_successful_read_ns'],0)
 def test_invalid_final_record_or_projection_never_commits_first_batch(self):
  for failure in ('record','projection'):
   directory,o=self.fixture([self.birth(),self.row()])
   error=C.Rejected('snapshot')
   if failure=='record':
    path=directory/'100.jsonl';path.write_bytes(path.read_bytes()+b'{}\n')
   context=mock.patch.object(o,'_project_diagnostics',side_effect=error) if failure=='projection' else mock.patch.object(O.time,'monotonic_ns',return_value=10)
   with context,mock.patch.object(O.time,'monotonic_ns',return_value=10),self.assertRaises(C.Rejected) as raised:o.read()
   if failure=='projection':self.assertIs(raised.exception,error)
   self.assertIsNone(o._first_failure);self.assertEqual(o._successful_reads,0)
 def test_candidate_validation_happens_before_original_final_deadline_check(self):
  directory,o=self.fixture([self.birth(),self.row()],deadline=100)
  clock=[10];original=C.validate_observer_failure_diagnostic
  def validate(value):
   result=original(value);clock[0]=100;return result
  with mock.patch.object(O.time,'monotonic_ns',side_effect=lambda:clock[0]),mock.patch.object(C,'validate_observer_failure_diagnostic',side_effect=validate):
   with self.assertRaises(C.Rejected) as raised:o.read()
  self.assertEqual(raised.exception.code,'deadline');self.assertIsNone(o._first_failure)
 def test_diagnostic_validation_fault_and_range_overflow_do_not_replace_original_result(self):
  for failure in ('validator','read_count','elapsed'):
   directory,o=self.fixture([self.birth(),self.row()])
   if failure=='read_count':o._successful_reads=2**31-1
   if failure=='elapsed':o._first_successful_read_ns=-C.ORIGINAL_NS
   context=mock.patch.object(C,'validate_observer_failure_diagnostic',side_effect=RuntimeError('private')) if failure=='validator' else mock.patch.object(O.time,'sleep')
   with context:self.assertEqual(self.read(o),[self.birth(),self.row()])
   self.assertEqual(o.first_failure_observation(),C.unavailable_first_failure_observation())
   self.read(o,30,31) # Must not relabel a later successful batch as the first.
   self.assertEqual(o.first_failure_observation(),C.unavailable_first_failure_observation())
 def test_rejected_later_read_never_overwrites_previous_origin(self):
  directory,o=self.fixture([self.birth(),self.row()]);self.read(o);before=o.first_failure_observation()
  path=directory/'100.jsonl';path.write_bytes(path.read_bytes()+b'{}\n')
  with self.assertRaises(C.Rejected):self.read(o,20,21)
  self.assertEqual(o.first_failure_observation(),before)
 def test_all_four_kinds_and_role_restrictions_use_existing_closed_facts(self):
  rows=[self.row(),T.NativeFailureBoundaryTests().record(),
        self.row('Host','HostFailureBoundary',facts=dict(version=1,stage='HostOpen',**{'class':'IoPermissionDenied'},relay=None)),
        self.row('Signer1','ActorFailureBoundary',facts=dict(version=1,driver={'stage':'OriginalActors','class':'IoPermissionDenied'},listener=None,origin=None))]
  for row in rows:C.validate_observer_failure_diagnostic(self.value([self.event(row)]))
  for index,role in ((1,'Signer1'),(2,'Coordinator')):
   event=self.event(rows[index]);event['role']=role
   with self.assertRaises(C.Rejected):C.validate_observer_failure_diagnostic(self.value([event]))
  event=self.event(rows[3]);event['role']='Host';event['facts']['listener']={'stage':'BoundsSource','class':'IoPermissionDenied'}
  with self.assertRaises(C.Rejected):C.validate_observer_failure_diagnostic(self.value([event]))
 def test_contract_rejects_forged_duplicate_out_of_order_or_unbounded_data(self):
  good=self.value([self.event(self.row())]);cases=[]
  for key,value in [('role','private'),('kind','Birth'),('sequence',0),('sequence',C.MAX_RECORDS+1),('sequence',True),('actor_elapsed_ns',-1),('actor_elapsed_ns',C.ORIGINAL_NS+1),('facts',{'code':'private'}),('facts',{'code':'source_failure','private':'secret'})]:
   bad=copy.deepcopy(good);bad['first_observed']['events'][0][key]=value;cases.append(bad)
  for key,value in [('read_index',0),('read_index',2**31),('read_index',True),('since_first_successful_read_ns',-1),('since_first_successful_read_ns',C.ORIGINAL_NS+1),('events',[]),('availability','Unavailable')]:
   bad=copy.deepcopy(good);bad['first_observed'][key]=value;cases.append(bad)
  for events in ([self.event(self.row())]*2,[self.event(self.row('Signer1')),self.event(self.row())]):
   bad=copy.deepcopy(good);bad['first_observed']['events']=events;cases.append(bad)
  cases.extend([dict(good,site='private'),dict(good,version=True),dict(good,raw='secret')])
  for bad in cases:
   with self.subTest(bad=bad),self.assertRaises(C.Rejected):C.validate_observer_failure_diagnostic(bad)
 def test_unavailable_is_exact_and_maximal_legal_events_fit_unchanged_wire_cap(self):
  unavailable=dict(version=1,site='Unclassified',first_observed=C.unavailable_first_failure_observation())
  C.validate_observer_failure_diagnostic(unavailable)
  for key,value in [('read_index',1),('since_first_successful_read_ns',0),('events',[self.event(self.row())])]:
   bad=copy.deepcopy(unavailable);bad['first_observed'][key]=value
   with self.assertRaises(C.Rejected):C.validate_observer_failure_diagnostic(bad)
  events=[]
  for role in C.ROLES:
   facts=dict(version=1,**{slot:{'stage':max(stages,key=len),'class':max(C.ACTOR_CLASSES,key=len)} for slot,stages in [('driver',C.ACTOR_DRIVER_STAGES),('listener',C.ACTOR_LISTENER_STAGES),('origin',C.ACTOR_ORIGIN_STAGES)]})
   if role not in ('Signer1','Signer2'):facts['listener']=None
   facts['origin']['peer']=max(C.ROLES,key=len)
   events.append(self.event(self.row(role,'ActorFailureBoundary',C.MAX_RECORDS,C.ORIGINAL_NS,facts)))
  value=self.value(events);value['site']=max(C.OBSERVER_FAILURE_SITES,key=len)
  value['first_observed'].update(read_index=2**31-1,since_first_successful_read_ns=C.ORIGINAL_NS)
  C.validate_observer_failure_diagnostic(value)
  self.assertLessEqual(len(('CI_FINANCIAL_OBSERVER_FAILURE_DIAGNOSTIC '+json.dumps(value,separators=(',',':'))+'\n').encode()),8192)
 def test_site_first_wins_preserves_same_exception_operation_count_and_guard_outcome(self):
  for code in ('observer_failure','deadline','snapshot','record_shape'):
   error=C.Rejected(code);operation=mock.Mock(side_effect=error)
   with self.assertRaises(C.Rejected) as raised:C.observer_failure_checked('FlowFailureRecord',C.observer_failure_checked,'DirectoryIdentity',operation)
   self.assertIs(raised.exception,error);operation.assert_called_once_with()
   self.assertEqual(getattr(error,'observer_failure_site',None),'DirectoryIdentity' if code=='observer_failure' else None)
  sentinel=object();self.assertIs(C.observer_failure_checked('FlowFailureRecord',lambda:sentinel),sentinel)
  for site in ('Unclassified','private',[],1):
   error=C.Rejected('observer_failure');self.assertIs(C.observer_failure_at(site,error),error)
   self.assertFalse(hasattr(error,'observer_failure_site'))
 def test_actual_read_io_directory_identity_and_final_prefix_sites(self):
  directory,o=self.fixture([self.birth()])
  with mock.patch.object(O.os,'open',side_effect=OSError('private')):
   with self.assertRaises(C.Rejected) as raised:self.read(o)
  self.assertEqual(raised.exception.observer_failure_site,'ReadIo')
  o._directory_identity=(-1,-1)
  with self.assertRaises(C.Rejected) as raised:self.read(o)
  self.assertEqual(raised.exception.observer_failure_site,'DirectoryIdentity')
  directory,o=self.fixture([self.birth()]);path=directory/'100.jsonl';path.write_bytes(path.read_bytes()+b'{')
  with self.assertRaises(C.Rejected) as raised:self.read(o,final=True)
  self.assertEqual(raised.exception.observer_failure_site,'FinalPrefixChanged')
 def test_actual_output_oracles_and_normal_close_preserve_guard_codes_and_no_input(self):
  external=T.F.load('ci-financial-external-output');full=T.F.load('ci-financial-output')
  for oracle,site,args in ((external,'ExternalOutputFailureRecord',(None,C.SEMANTIC_PROFILE)),(full,'FullOutputFailureRecord',())):
   row=self.row();row['profile']=C.PROFILE if oracle is full else C.SEMANTIC_PROFILE
   with self.assertRaises(oracle.C.Rejected) as raised:oracle.validate_completed([row],100,0,*args)
   self.assertEqual(raised.exception.code,'observer_failure');self.assertEqual(raised.exception.observer_failure_site,site)
  controller=mock.Mock();native=T.F.S.NativeScenario(controller,mock.Mock(),mock.Mock())
  with self.assertRaises(T.F.S.C.Rejected) as raised:native.close_after_normal_proof([T.NativeFailureBoundaryTests().record()],None,C.SEMANTIC_PROFILE)
  self.assertEqual(raised.exception.observer_failure_site,'NormalCloseFailureBoundary');controller.terminal_click.assert_not_called()
 def test_actual_post_snapshot_flow_failure_site_preserves_first_reason(self):
  fixture=T.ExactPrefixValidationTests();fixture.addCleanup=self.addCleanup
  path,rows,o=fixture.fixture();o.deadline_ns=10**30;original=o.read;calls=[]
  def read(**kwargs):
   result=original(**kwargs);calls.append(1)
   if len(calls)==1:
    with path.open('ab') as stream:stream.write(json.dumps(self.row(sequence=5,elapsed=5)).encode()+b'\n')
   return result
  o.read=read;controller=mock.Mock();flow=T.F.FullFlow(controller,mock.Mock(deadline_ns=o.deadline_ns),o,None)
  with self.assertRaises(T.F.C.Rejected) as raised:flow.snapshot()
  self.assertEqual(raised.exception.code,'observer_failure');self.assertEqual(raised.exception.observer_failure_site,'FlowFailureRecord')
  self.assertEqual(o.first_failure_observation()['events'][0]['facts'],{'code':'source_failure'})
  controller.click.assert_not_called()

if __name__=='__main__':unittest.main()
