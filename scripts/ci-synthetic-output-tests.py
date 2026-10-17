#!/usr/bin/env python3
"""Pure public parser/selection tests. No child, socket, key or wallet is created."""
import importlib.util
import json
import pathlib
import re
import unittest

ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('ci_output', ROOT/'scripts/ci-synthetic-output.py')
output=importlib.util.module_from_spec(spec)
spec.loader.exec_module(output)

class PublicOutputTests(unittest.TestCase):
    def record(self):
        row={key:False for key in output.FALSE_FIELDS}
        row.update({key:1 for key in output.INT_FIELDS})
        row.update(evidence_kind='synthetic_full_payment_v1',transaction_id='a'*64,
                   transaction_bytes_sha256='b'*64,network='testnet',
                   submission_outcome='synthetic_acknowledged',consensus_branch_id=0x77190ad9,
                   expiry_height=100,recipient_decrypted_zatoshis=100000,
                   fabricated_tip_height=3,required_confirmations=3)
        return row

    def test_core_policy_reports_only_unmodified_process_policy(self):
        line='[JOINED_CORE_POLICY inherited_limit=Zero collector=Pipe process_dumpability=Unchanged crash_copy_absence_verified=false]'
        self.assertIsNotNone(output.CORE.fullmatch(line))
        self.assertIsNone(output.CORE.fullmatch(line.replace('Unchanged','Disabled')))
        self.assertIsNone(output.CORE.fullmatch(line.replace('verified=false','verified=true')))

    def test_exact_listing_requires_one_named_test_and_summary(self):
        name=output.TESTS['initial'][0]
        known=name+': test\n\n1 test, 0 benchmarks\n'
        self.assertTrue(output.exact_listing(known,name))
        self.assertTrue(output.exact_listing(known.rstrip('\n'),name))
        for invalid in ['',name+': test\n','0 tests, 0 benchmarks\n',known+'private',
                        known.replace('1 test','2 tests'),known.replace(name,'another'),
                        name+': test\nanother: test\n\n2 tests, 0 benchmarks\n']:
            self.assertFalse(output.exact_listing(invalid,name))

    def test_public_outcome_exact_positive(self):
        row=self.record()
        self.assertEqual(output.public_outcome(json.dumps(row)),row)
        self.assertEqual(len(row),20)

    def test_public_outcome_unknown_duplicate_missing_or_stronger_claims_refused(self):
        row=self.record()
        cases=[dict(row,private='forbidden'),{k:v for k,v in row.items() if k!='schema'}]
        cases.extend(dict(row,**{k:True}) for k in output.FALSE_FIELDS)
        for value in cases:
            with self.assertRaises(ValueError): output.public_outcome(json.dumps(value))
        with self.assertRaises(ValueError):
            output.public_outcome(json.dumps(row)[:-1]+',"schema":1}')

    def test_public_outcome_numeric_digest_and_size_bounds(self):
        for field,value in [('schema',True),('expiry_height',2**32),('schema',2**16),
                            ('recipient_decrypted_zatoshis',2**64),('required_confirmations',33),
                            ('fabricated_inclusion_height',4),('transaction_id','C'*64),
                            ('submission_attempt',2),('network','mainnet')]:
            with self.assertRaises(ValueError): output.public_outcome(json.dumps(dict(self.record(),**{field:value})))
        with self.assertRaises(ValueError): output.public_outcome(' '*4097)

    def failure(self,summary='SingleIpcBind:IoKind=PermissionDenied:errno=1'):
        return '[JOINED_FAILURE exit=Some(101) signal=None core_dumped=false inputs=1/2 static_boundaries='+summary+']'

    def test_closed_failure_labels_and_canonical_errno(self):
        for summary in ['none','FullCurrentDispatch:Begin',
                        'SingleIpcBind:IoKind=PermissionDenied:errno=1',
                        'SingleIpcBind:IoKind=Other:errno=-2147483648']:
            self.assertTrue(output.safe_failure(self.failure(summary)))
        for summary in ['private:Begin','SingleIpcBind:private',
                        'SingleIpcBind:IoKind=Other:errno=+1',
                        'SingleIpcBind:IoKind=Other:errno=2147483648',
                        'SingleIpcBind:IoKind=Other:errno=-0',
                        ','.join(['FullCurrentDispatch:Begin']*65)]:
            self.assertFalse(output.safe_failure(self.failure(summary)))
        self.assertFalse(output.safe_failure(self.failure().replace('Some(101)','Some(2147483648)')))
        self.assertFalse(output.safe_failure(self.failure().replace('inputs=1/2','inputs=3/2')))

    def test_projection_does_not_search_inside_private_text(self):
        name=output.TESTS['initial'][0]
        marker=self.failure()
        self.assertEqual(output.public_line(marker.encode(),name),('failure',marker))
        self.assertEqual(output.public_line(('test '+name+' ... '+marker).encode(),name),('failure',marker))
        for value in ['private '+marker,'test unknown ... '+marker,marker+' private','private wallet bytes']:
            self.assertIsNone(output.public_line(value.encode(),name))
        self.assertIsNone(output.public_line(b'x'*8193,name))

    def test_failure_enum_sets_match_compiled_source(self):
        path=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/safe_diagnostics_v1.rs'
        text=path.read_text()
        for kind,expected in [('Boundary',output.BOUNDARIES),('Outcome',output.OUTCOMES)]:
            body=re.search(r'labels! \{ '+kind+r' \{(.*?)\} \}',text,re.S).group(1)
            self.assertEqual(frozenset(x.strip() for x in body.split(',') if x.strip()),expected)

    def test_oversized_physical_line_never_promotes_its_marker_suffix(self):
        framing=output.BoundedLines()
        marker=self.failure().encode()
        self.assertEqual(framing.feed(b'private'+b'x'*8193),[])
        self.assertEqual(framing.feed(marker),[])
        self.assertEqual(framing.feed(b'\n'),[])
        self.assertEqual(framing.feed(marker+b'\n'),[marker])
        # Also reject a single oversized complete chunk and resume next line.
        self.assertEqual(framing.feed(b'x'*8193+marker+b'\n'+marker+b'\n'),[marker])

    def test_pure_preflight_is_exactly_the_eighteen_reviewed_cases(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
        expected=[]
        for leaf in ['owned_test_process_group_v1','owned_tls_child_v1','process_containment_v1','public_outcome_v1']:
            module='tests' if leaf=='public_outcome_v1' else 'pure_tests'
            names=re.findall(r'#\[test\]\s+fn (\w+)\(', (base/(leaf+'.rs')).read_text())
            # This helper is a child of the provider TLS module, not qualification.
            scope='synthetic_provider_tls_v1::owned_tls_child_v1' if leaf=='owned_tls_child_v1' else leaf
            expected.extend(output.PREFIX+scope+'::'+module+'::'+name for name in names)
            if leaf=='owned_tls_child_v1':
                self.assertIn('mod owned_tls_child_v1;', (base/'synthetic_provider_tls_v1.rs').read_text())
        self.assertEqual(len(expected),18)
        self.assertEqual(tuple(expected),output.PURE_TESTS)
        self.assertNotIn(output.TESTS['initial'][0],expected)
        self.assertNotIn(output.TESTS['full'][0],expected)

    def test_ci_temporary_socket_path_budget(self):
        # Includes this runner's extra short TMPDIR layer, not merely /tmp.
        for inner in ['wholepact-born-manual-ipc-','wholepact-born-stop-','.tmp']:
            path='/tmp/wpc.aaaaaa/wp-pty-bbbbbb/'+inner+'cccccc/requests-'+'0'*24+'.sock'
            self.assertLess(len(path.encode()),108)

if __name__=='__main__':
    unittest.main()
