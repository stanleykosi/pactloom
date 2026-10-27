"""Pure returned-operation diagnostic contract checks; never compile/run native code."""
import ast
import copy
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/file)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module

C=load('restriction_return_contract','ci-financial-contract.py')
ORIGIN=ROOT/'crates/wholepact-financial-coordinator-origin/src'
SINGLE=('RestrictionCore','RestrictionSession','RestrictionAlreadyRevoked','RestrictionPairService')
PAIRS=('V3Active','EntryPreparing','EntryCustody','EntryAction','ContinueMissing',
       'ContinuePreparing','ContinueBindingMissing','ContinueBinding','ReadBindingMissing',
       'ReadCurrent','AdmitActive','WriterActive','ActivateActive','WitnessActive',
       'HistoryActive','SigningActive')
STAGES=SINGLE+tuple('RestrictionOwner'+str(owner)+part for part in PAIRS for owner in (1,2))
NATIVE_TESTS=tuple('financial_ci_actor_diagnostics::tests::'+name for name in (
    'restriction_return_details_preserve_error_identity_and_first_slots',
    'restriction_return_success_keeps_failure_gate_and_details_empty',
    'restriction_return_stage_inventory_stays_append_only_and_bounded'))

def actor(stage):
    return dict(version=1,driver=dict(stage=stage,**{'class':'IoPermissionDenied'}),listener=None,origin=None)

def diagnostic(events):
    return dict(version=1,site='NextSnapshotFailureRecords',first_observed=dict(
        availability='Observed',read_index=2**31-1,since_first_successful_read_ns=C.ORIGINAL_NS,events=events))

def event(role,facts):
    return dict(role=role,kind='ActorFailureBoundary',sequence=C.MAX_RECORDS,
                actor_elapsed_ns=C.ORIGINAL_NS,facts=facts)

class RestrictionReturnContractTests(unittest.TestCase):
    def test_exact_append_only_native_python_vocabulary_and_discriminant_bound(self):
        source=(ORIGIN/'financial_ci_actor_diagnostics.rs').read_text()
        names=source.split('codes!(DriverStage {',1)[1].split('});',1)[0].split(',')
        self.assertEqual(len(names),211);self.assertLessEqual(len(names),256)
        self.assertEqual(hashlib.sha256('\n'.join(names[:175]).encode()).hexdigest(),
                         '44c30eff24de3cd6bbb1ca63bff732eb383acdedaf7c617f1b23a359e231e975')
        self.assertEqual(tuple(names[175:]),STAGES)
        self.assertEqual(set(names),C.ACTOR_DRIVER_STAGES)
        self.assertEqual(len(set(names)),len(names))
    def test_all_new_stages_survive_actual_actor_and_first_observation_validators(self):
        for stage in STAGES:
            for role in ('Coordinator','Signer2'):
                with self.subTest(stage=stage,role=role):
                    facts=actor(stage);self.assertIs(C.validate_actor_failure_facts(facts,role),facts)
                    value=diagnostic([event(role,facts)])
                    self.assertIs(C.validate_observer_failure_diagnostic(value),value)
                    self.assertEqual(json.loads(json.dumps(value)),value)
    def test_unknown_stages_classes_and_raw_payload_stay_rejected(self):
        for change in (dict(stage='RestrictionOwner3ContinueBinding'),dict(stage='RestrictionCore raw'),
                       {'class':'private/path'},dict(payload='raw error')):
            value=diagnostic([event('Coordinator',actor(STAGES[0]))])
            value['first_observed']['events'][0]['facts']['driver'].update(change)
            with self.subTest(change=change),self.assertRaises(C.Rejected):
                C.validate_observer_failure_diagnostic(value)
    def test_maximal_closed_vocabulary_wire_stays_within_original_limits(self):
        longest=lambda values:max(values,key=lambda value:(len(value),value))
        rows=[]
        for role in C.ROLES:
            facts=dict(version=1,driver=dict(stage=longest(C.ACTOR_DRIVER_STAGES),**{'class':longest(C.ACTOR_CLASSES)}),
                       listener=None,origin=dict(stage=longest(C.ACTOR_ORIGIN_STAGES),
                       **{'class':longest(C.ACTOR_CLASSES)},peer=longest(C.ACTOR_ROLES)))
            if role in ('Signer1','Signer2'):
                facts['listener']=dict(stage=longest(C.ACTOR_LISTENER_STAGES),**{'class':longest(C.ACTOR_CLASSES)})
            rows.append(event(role,facts))
        value=diagnostic(rows);value['site']=longest(C.OBSERVER_FAILURE_SITES)
        self.assertEqual(len(rows),17);C.validate_observer_failure_diagnostic(value)
        raw=json.dumps(value,separators=(',',':')).encode()
        self.assertLessEqual(len(raw),8000)
        self.assertLessEqual(len(b'CI_FINANCIAL_OBSERVER_FAILURE_DIAGNOSTIC '+raw),8192)
        bad=copy.deepcopy(value);bad['first_observed']['events'].append(copy.deepcopy(rows[0]))
        with self.assertRaises(C.Rejected):C.validate_observer_failure_diagnostic(bad)
    def test_exact_historical_restorers_keep_original_native_files(self):
        cause=load('restriction_return_cause','ci-financial-cause-trace.py')
        audit=load('restriction_return_audit','ci-financial-admit-read-source-audit.py')
        path='crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs'
        workflow=(ROOT/path).read_text();actor_source=(ORIGIN/'financial_ci_actor_diagnostics.rs').read_text()
        self.assertEqual(hashlib.sha256(cause.p89_restore(path,workflow).encode()).hexdigest(),
                         'a3a8c9da5b5699bcbc3866622b8e0d07b7a3e28223338754129939f5621301b0')
        self.assertEqual(hashlib.sha256(audit.restore_restriction_diagnostic(actor_source).encode()).hexdigest(),
                         'ddd37d79a6c1b5cf9715eddf29b2d9a6d3de5bbc1573e1a46de419d712d4228e')
    def test_live_enum_generator_uses_all_actual_values(self):
        generator=load('restriction_return_generator','ci-financial-admit-read-trace.py')
        texts,_=generator.extract(ROOT)
        stage=generator.item(texts['diagnostic'],'codes!(DriverStage {').split('{',1)[1].rsplit('}',1)[0]
        self.assertEqual(set(stage.split(',')),C.ACTOR_DRIVER_STAGES)
        self.assertEqual(len(stage.split(',')),211)
    def test_hosted_actual_compiler_profiles_precede_generated_traces_and_python(self):
        workflow=(ROOT/'.github/workflows/deadline-preflight.yml').read_text()
        self.assertEqual(workflow.count('parked-material-review-preflight-p91'),4)
        self.assertIn("for profile in ['minimal', 'production', 'observed-pixel', 'observed-semantic']:",workflow)
        self.assertIn("['cargo', 'check', '--locked', '-p', package, '--lib', '--no-default-features'",workflow)
        self.assertLess(workflow.index("args = rustup+['cargo', 'check'"),workflow.index("'scripts/ci-financial-cause-trace.py'"))
        self.assertLess(workflow.index('      - name: Pinned compiler'),workflow.index('      - name: Exact historical P40 adapter'))
        self.assertNotIn('--source-only',workflow)
        self.assertEqual(workflow.count('assert len(names) == 31 and len(set(names)) == 31'),1)
    def test_all_three_new_actual_native_tests_are_nonignored_exact_hosted_selections(self):
        workflow=(ROOT/'.github/workflows/deadline-preflight.yml').read_text()
        names=ast.literal_eval(re.search(r'semantic_names = (\[.*?\])',workflow,re.S).group(1))
        self.assertEqual(len(names),13);self.assertEqual(len(set(names)),13)
        self.assertEqual(tuple(names[-3:]),NATIVE_TESTS)
        source=(ORIGIN/'financial_ci_actor_diagnostics.rs').read_text()
        for name in NATIVE_TESTS:self.assertEqual(source.count('fn '+name.rsplit('::',1)[-1]+'('),1)
        gate=workflow.split('for name in semantic_names:',1)[1].split("print('Four clock",1)[0]
        for token in ("'--list', '--exact'","'--exact', name, '--test-threads=1'",'1 passed; 0 failed; 0 ignored;','timeout=30'):
            self.assertIn(token,gate)

if __name__=='__main__':unittest.main()
