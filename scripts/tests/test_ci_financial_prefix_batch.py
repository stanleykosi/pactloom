"""Actual ObserverFiles fresh-read compatibility; no cached evidence shortcut."""
import copy
import json
import pathlib
import tempfile
import time
import unittest
from unittest import mock
import test_ci_financial_observer as T
O=T.O

class PrefixBatchTests(unittest.TestCase):
 def fixture(self,records,encode=None):
  td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
  p=pathlib.Path(td.name)/'100.jsonl';encode=encode or (lambda r:json.dumps(r).encode())
  p.write_bytes(b''.join(encode(r)+b'\n' for r in records));p.chmod(0o600)
  return p,O.ObserverFiles(td.name,time.monotonic_ns()+60_000_000_000,O.C.SEMANTIC_PROFILE)
 def test_warm_prefix_uses_one_decode_but_returns_fresh_nested_objects(self):
  records=T.SameBatchValidationTests().records(20);p,o=self.fixture(records)
  a=o.read();a[1]['facts']['widgets'].append({'caller':'mutation'})
  with mock.patch.object(O.json,'loads',wraps=json.loads) as decode,mock.patch.object(O.C,'validate_record',wraps=O.C.validate_record) as validate:
   b=o.read();self.assertEqual(decode.call_count,1);self.assertEqual(validate.call_count,0)
  self.assertEqual(b,records);self.assertIsNot(b[1]['facts'],a[1]['facts'])
  row=copy.deepcopy(records[-1]);row['sequence']+=1;row['elapsed_ns']+=1;row['facts']['view_generation']+=1
  with p.open('ab') as stream:stream.write(json.dumps(row).encode()+b'\n')
  with mock.patch.object(O.json,'loads',wraps=json.loads) as decode,mock.patch.object(O.C,'validate_record',wraps=O.C.validate_record) as validate:
   self.assertEqual(o.read(),records+[row]);self.assertEqual(decode.call_count,2);self.assertEqual(validate.call_count,1)
  self.assertEqual(o.collection_diagnostic()['source_records'],len(records)+1)
  semantic=T.SemanticHostObserverTests();semantic.setUp();self.addCleanup(semantic.tearDown)
  records=semantic.records();p,o=self.fixture(records);first=o.read();text=o._semantic_active['text']
  first[1]['facts']['text']='caller replacement';first[1]['facts']['view']['rect'][0]=99
  self.assertEqual(o.read(),records);self.assertEqual(o.host_view(records[-1]['facts']),semantic.text)
  self.assertFalse(any(text));text=o._semantic_active['text']
  protected=copy.deepcopy(records[-1]);protected['sequence']+=1
  facts=protected['facts'];facts['view_generation']+=1;facts['host_view_id']=None;facts['host_input']=True
  facts['host_observation'].update(entry='Writing',view=None)
  with p.open('ab') as stream:stream.write(json.dumps(protected).encode()+b'\n')
  self.assertEqual(o.read(),records+[protected]);self.assertIsNone(o._semantic_active);self.assertFalse(any(text))
 def test_previously_accepted_encodings_and_json_whitespace_remain_compatible(self):
  records=T.SameBatchValidationTests().records(3)
  encoders=[lambda r:(' \t'+json.dumps(r)+' \r').encode(),
            lambda r:json.dumps(r).replace('Birth','Bi\\u0072th').encode(),
            lambda r:json.dumps(r).encode('utf-8-sig'),
            lambda r:json.dumps(r).encode('utf-16-le'),lambda r:json.dumps(r).encode('utf-16-be'),
            lambda r:json.dumps(r).encode('utf-32-le'),lambda r:json.dumps(r).encode('utf-32-be')]
  for encode in encoders:
   with self.subTest(encoding=encoders.index(encode)):
    p,o=self.fixture(records,encode);self.assertEqual(o.read(),records);self.assertEqual(o.read(),records)
  # Non-ASCII is not in this closed record vocabulary; it still fails strict
  # suffix validation rather than being admitted by the optimized prefix.
  for suffix in (b'{"kind":"Birth","kind":"Birth"}',b'{"n":NaN}',b'{"private":"\xc3\xa9"}',b'{}'):
   p,o=self.fixture(records);o.read()
   with p.open('ab') as stream:stream.write(suffix+b'\n')
   with self.assertRaises(O.C.Rejected):o.read()
 def test_fresh_prefix_identity_profile_and_size_guards_still_precede_reuse(self):
  records=T.SameBatchValidationTests().records(3)
  for change in ('rewrite','truncate','identity','profile','count','line'):
   with self.subTest(change=change):
    p,o=self.fixture(records);o.read();raw=p.read_bytes()
    if change=='rewrite':p.write_bytes(raw.replace(b'Signer1',b'Signer2',1))
    elif change=='truncate':p.write_bytes(raw[:-1])
    elif change=='identity':p.rename(p.with_suffix('.old'));p.write_bytes(raw);p.chmod(0o600);p.with_suffix('.old').unlink()
    elif change=='profile':o.expected_profile=O.C.EXTERNAL_PROFILE
    context=mock.patch.object(O.C,'MAX_RECORDS',1) if change=='count' else mock.patch.object(O.C,'MAX_RECORD_BYTES',1) if change=='line' else mock.patch.object(O.C,'MAX_RECORDS',O.C.MAX_RECORDS)
    with context,self.assertRaises(O.C.Rejected):o.read()
 def test_failed_linkage_is_not_cached_as_success_and_partial_suffix_stays_pending(self):
  records=T.SameBatchValidationTests().records(3);p,o=self.fixture(records);o.read();before=o.failure_diagnostics()
  row=copy.deepcopy(records[-1]);row['sequence']+=1
  encoded=json.dumps(row).encode()
  with p.open('ab') as stream:stream.write(encoded)
  self.assertEqual(o.read(),records)
  with p.open('ab') as stream:stream.write(b'\n')
  for _ in range(2):
   with self.assertRaises(O.C.Rejected) as e:o.read()
   self.assertEqual(e.exception.code,'replay')
  # Shape receipts may exist after the first rejected join, but every read
  # still executes the full original semantic linkage and never returns it.
  self.assertEqual(o.failure_diagnostics()['progress'],before['progress'])
 def test_full_fresh_read_and_original_collection_checks_remain_in_actual_path(self):
  records=T.SameBatchValidationTests().records(3);p,o=self.fixture(records);o.read()
  with mock.patch.object(O.os,'open',wraps=O.os.open) as opened,\
       mock.patch.object(O.C,'_native_failure_sequence_validated',wraps=O.C._native_failure_sequence_validated) as native,\
       mock.patch.object(O.C,'validate_host_exit_cardinality',wraps=O.C.validate_host_exit_cardinality) as host,\
       mock.patch.object(O.C,'validate_actor_cardinality',wraps=O.C.validate_actor_cardinality) as actor,\
       mock.patch.object(O.C,'_join_host_views_validated',wraps=O.C._join_host_views_validated) as join,\
       mock.patch.object(o,'_project_diagnostics',wraps=o._project_diagnostics) as projection:
   self.assertEqual(o.read(),records)
  self.assertEqual(opened.call_count,1)
  for check in (native,host,actor,join,projection):check.assert_called_once()
  self.assertEqual(o._files['100.jsonl'][1],p.read_bytes())

if __name__=='__main__':unittest.main()
