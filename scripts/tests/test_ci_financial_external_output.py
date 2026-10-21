"""Fabricated observation fixtures test rejection logic, never a native pass."""
import copy
import importlib.util
import pathlib
import sys
import unittest
from test_ci_financial_output import observations
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('financial_external_output_tested',ROOT/'ci-financial-external-output.py')
O=importlib.util.module_from_spec(spec);sys.modules[spec.name]=O;spec.loader.exec_module(O)
C=O.C

def external_case():
    records=[]
    for record in observations():
        record['profile']=C.EXTERNAL_PROFILE
        if record['role'] in C.INERT_WITNESSES and record['kind'] in ('PurposeServing','PurposeDisposed'):continue
        if record['role'] in C.INERT_WITNESSES and record['kind']=='PurposeClosed':record['kind']='InertStopped'
        if record['kind']=='SignerMilestone' and record['facts']['step']=='FinancialEntryOpened':
            snapshot=copy.deepcopy(record);snapshot['kind']='UiSnapshot'
            snapshot['facts']=dict(phase='Selecting',subphase='None',owner=None,view_generation=len(records)+1,
                focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=[])
            records.append(snapshot)
        records.append(record)
    sequence={role:0 for role in C.ROLES}
    for record in records:sequence[record['role']]+=1;record['sequence']=sequence[record['role']]
    gates=[]
    for owner in ('Signer1','Signer2'):
        if owner=='Signer2':
            actual=next(r for r in records if r['kind']=='SignerMilestone' and r['facts']=={'owner':'Signer1','step':'SigningRetired'})
            gates.append(dict(owner=owner,gate='start',role=actual['role'],sequence=actual['sequence']))
        audited=next(r for r in records if r['kind']=='SignerMilestone' and r['facts']=={'owner':owner,'step':'AdmissionAudited'})
        financial=next(r for r in records if r['kind']=='SignerMilestone' and r['facts']=={'owner':owner,'step':'FinancialEntryOpened'})
        snapshot=next(r for r in records if r['kind']=='UiSnapshot' and r['elapsed_ns']==financial['elapsed_ns'])
        for kind,actual in [('audit_stop',audited),('financial_entry',snapshot)]:
            gates.append(dict(owner=owner,gate=kind,role=actual['role'],sequence=actual['sequence']))
    steps=('bootstrap_serving','bootstrap_drained','admission_committed','admission_drained','audit_serving','audit_drained','transport_parked')
    evidence=dict(profile=C.EXTERNAL_PROFILE,events=[dict(version=1,owner=owner,event=step) for owner in ('signer1','signer2') for step in steps],
        gates=gates,cleanup=dict(version=1,actual_child_pid=501,actual_wait_status=dict(exit_code=None,signal=9),owned_group_absent=True,root_absent=True),
        actual_fixture_parent_pid=500,actual_fixture_parent_exit=0)
    return records,evidence

class ExternalOracleTests(unittest.TestCase):
    def test_seven_services_never_claim_thirteen(self):
        records,external=external_case();proof=O.validate_completed(records,100,0,external)
        value=O.public_result(proof,exact_build_verified=True,container_removed=True)
        self.assertFalse(value['synthetic_full_native_verified']);self.assertEqual(value['integrated_witness_services'],7)
        self.assertEqual(value['retained_inert_witnesses'],6)
    def test_every_external_native_step_required(self):
        for index in range(14):
            records,external=external_case();external['events'].pop(index)
            with self.assertRaises(Exception):O.validate_completed(records,100,0,external)
    def test_every_actual_gate_required(self):
        for index in range(5):
            records,external=external_case();external['gates'].pop(index)
            with self.assertRaises(Exception):O.validate_completed(records,100,0,external)
    def test_missing_inert_stopped_rejected(self):
        records,external=external_case();records=[r for r in records if r['kind']!='InertStopped']
        with self.assertRaises(Exception):O.validate_completed(records,100,0,external)
    def test_fixture_markers_do_not_replace_actual_cleanup(self):
        for field in ('owned_group_absent','root_absent'):
            records,external=external_case();external['cleanup'][field]=False
            with self.assertRaises(Exception):O.validate_completed(records,100,0,external)
    def test_gate_cannot_reference_wrong_actual_record(self):
        records,external=external_case();external['gates'][0]['sequence']=1
        with self.assertRaises(Exception):O.validate_completed(records,100,0,external)
