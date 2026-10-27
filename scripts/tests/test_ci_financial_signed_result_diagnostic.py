"""Finite SignedResult driver wire checks; no compiler, native run or network."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import re
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('signed_result_diagnostic_contract',ROOT/'scripts/ci-financial-contract.py')
C=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(C)
NATIVE=ROOT/'crates/wholepact-financial-coordinator-origin/src/financial_ci_actor_diagnostics.rs'
SUFFIXES=('OriginalDeadline','EntryBounds','SharedWallRead','SharedWallRejected','ServiceWallBefore','ServiceWallExpired','Restricted','SigningPhase','RetiredIndex','RetiredRoot','Core','FinalRestricted')
APPENDED=tuple('SignedResultOwner'+str(owner)+suffix for suffix in SUFFIXES for owner in (1,2))+('SigningOwner1RetiredMissing','SigningOwner2RetiredMissing')

def facts(stage='Receive',mask=None):
    driver=dict(stage=stage,**{'class':'IoPermissionDenied'})
    if mask is not None:driver['minimum_bounds']=mask
    return dict(version=1,driver=driver,listener=None,origin=None)

def encoded(value):return json.dumps(value,separators=(',',':')).encode()

def largest_failures():
    longest=lambda names:max(names,key=lambda n:(len(n),n))
    cls=longest(C.ACTOR_CLASSES)
    old=C.ACTOR_DRIVER_STAGES-C.ACTOR_SIGNED_RESULT_STAGES
    result={}
    for role in C.ROLES:
        candidates=[dict(stage=stage,**{'class':cls}) for stage in old]
        if role=='Coordinator':
            candidates.extend(dict(stage=stage,**{'class':cls},**({'minimum_bounds':15} if stage in C.ACTOR_SIGNED_MINIMUM_STAGES else {})) for stage in C.ACTOR_SIGNED_RESULT_STAGES)
        driver=max(candidates,key=lambda d:(len(encoded(d)),d['stage']))
        listener=dict(stage=longest(C.ACTOR_LISTENER_STAGES),**{'class':cls}) if role in ('Signer1','Signer2') else None
        origin=dict(stage=longest(C.ACTOR_ORIGIN_STAGES),**{'class':cls},peer=longest(C.ACTOR_ROLES))
        result[role]=dict(driver=driver,listener=listener,origin=origin)
    return result

class SignedResultDiagnosticTests(unittest.TestCase):
    def test_native_and_python_append_only_inventory_matches_exact_original_prefix(self):
        raw=NATIVE.read_bytes().decode('utf-8')
        names=tuple(re.search(r'codes!\(DriverStage \{([^}]+)\}\);',raw).group(1).split(','))
        self.assertEqual(len(names),237);self.assertEqual(len(set(names)),237)
        self.assertEqual(names[211:],APPENDED)
        self.assertEqual(hashlib.sha256(','.join(names[:211]).encode()).hexdigest(),'6dab80dfd81e08cd4535f8018af4b1b01b5e719ef77d4c963140806e4ed95051')
        self.assertEqual(set(names),C.ACTOR_DRIVER_STAGES)
        self.assertEqual(set(APPENDED),C.ACTOR_SIGNED_RESULT_STAGES)
        self.assertEqual(C.ACTOR_SIGNED_MINIMUM_STAGES,{'SignedResultOwner1OriginalDeadline','SignedResultOwner2OriginalDeadline'})
        self.assertLessEqual(len(names),256)

    def test_all_fifteen_minimum_tie_masks_for_both_owners_are_closed(self):
        for owner in (1,2):
            for mask in range(1,16):
                with self.subTest(owner=owner,mask=mask):
                    f=facts('SignedResultOwner'+str(owner)+'OriginalDeadline',mask)
                    self.assertIs(C.validate_actor_failure_facts(f,'Coordinator'),f)
                    d=C.unavailable_actor_diagnostic();d['actors']['Coordinator']['failure']={k:f[k] for k in ('driver','listener','origin')}
                    self.assertIs(C.validate_actor_diagnostic(d),d)
        # This is an immutable-minimum identity mask, not elapsed/remaining time.
        self.assertIn('service=1, writer=2, writer_wall=4, entry.original_source=8',NATIVE.read_text())

    def test_new_stages_require_actual_coordinator_role_not_unknown_or_other_actor(self):
        for stage in APPENDED:
            f=facts(stage,1 if stage in C.ACTOR_SIGNED_MINIMUM_STAGES else None)
            C.validate_actor_failure_facts(f,'Coordinator')
            for role in [None,'Unknown',*(r for r in C.ROLES if r!='Coordinator')]:
                with self.subTest(stage=stage,role=role),self.assertRaises(C.Rejected):
                    C.validate_actor_failure_facts(f,role)

    def test_minimum_field_is_mandatory_only_on_two_deadline_stages(self):
        for stage in C.ACTOR_SIGNED_MINIMUM_STAGES:
            with self.assertRaises(C.Rejected):C.validate_actor_failure_facts(facts(stage),'Coordinator')
            for value in (False,True,None,0,-1,16,255,1.0,'1',[],{}):
                f=facts(stage);f['driver']['minimum_bounds']=value
                with self.subTest(stage=stage,value=value),self.assertRaises(C.Rejected):C.validate_actor_failure_facts(f,'Coordinator')
            f=facts(stage,1);f['driver']['peer']='Signer1'
            with self.assertRaises(C.Rejected):C.validate_actor_failure_facts(f,'Coordinator')
        for stage in C.ACTOR_DRIVER_STAGES-C.ACTOR_SIGNED_MINIMUM_STAGES:
            for mask in (None,0,1):
                f=facts(stage);f['driver']['minimum_bounds']=mask
                with self.subTest(stage=stage,mask=mask),self.assertRaises(C.Rejected):C.validate_actor_failure_facts(f,'Coordinator')
        for slot in ('listener','origin'):
            f=facts();f[slot]=dict(stage=next(iter(C.ACTOR_LISTENER_STAGES if slot=='listener' else C.ACTOR_ORIGIN_STAGES)),**{'class':'IoOther'},minimum_bounds=1)
            if slot=='origin':f[slot]['peer']=None
            with self.assertRaises(C.Rejected):C.validate_actor_failure_facts(f,'Signer1')

    def test_all_old_driver_shapes_and_classes_remain_identical(self):
        for stage in C.ACTOR_DRIVER_STAGES-C.ACTOR_SIGNED_RESULT_STAGES:
            for cls in C.ACTOR_CLASSES:
                f=facts(stage);f['driver']['class']=cls;before=encoded(f)
                self.assertIs(C.validate_actor_failure_facts(f,'Signer1'),f)
                self.assertEqual(encoded(f),before)
                self.assertEqual(set(f['driver']),{'stage','class'})
        self.assertEqual(encoded(facts()),b'{"version":1,"driver":{"stage":"Receive","class":"IoPermissionDenied"},"listener":null,"origin":null}')

    def test_native_raw_decoder_and_specialized_latch_are_separate_from_failure_gate(self):
        raw=NATIVE.read_text()
        self.assertIn('if value>>20!=0{return None;}',raw)
        self.assertIn('let value=1+code as u32+((class as u32)<<8)+((minimum_bounds as u32)<<16);',raw)
        self.assertIn('self.driver.compare_exchange(0,value,Ordering::Relaxed,Ordering::Relaxed)',raw)
        line=next(line for line in raw.splitlines() if line.startswith('pub(crate) fn driver_minimum_detail('))
        self.assertIn('SLOTS.latch_driver(pid(),stage,class,minimum_bounds)',line)
        self.assertIn('if minimum_driver_stage(stage as u8)',line)
        self.assertNotIn('mark_failed',line)
        self.assertIn('pub fn driver(stage:DriverStage,class:Class){driver_detail(stage,class);mark_failed();}',raw)
        self.assertIn('#[serde(skip_serializing_if="Option::is_none")]',raw)
        for test in ('signed_result_minimum_masks_keep_atomic_detail_and_legacy_shape','signed_result_driver_rejects_invalid_bits_masks_roles_and_pids','signed_result_driver_first_wins_never_mixes_owner_class_or_mask','signed_result_stage_inventory_preserves_all_original_discriminants'):
            self.assertEqual(raw.count('#[test] fn '+test+'()'),1)

    def test_largest_valid_actor_and_first_observation_wires_stay_bounded(self):
        failures=largest_failures();actor=C.unavailable_actor_diagnostic()
        for role in C.ROLES:
            actor['actors'][role]['failure']=failures[role]
            parents=[parent for parent,children in C.ACTOR_REAP_OWNERS.items() if role in children]
            if parents:actor['actors'][role]['reap']=dict(parent=max(parents,key=len),context='RetirementTryReap',exit_code=255,signal=None)
        C.validate_actor_diagnostic(actor)
        self.assertEqual(len(actor['actors']),17)
        self.assertLessEqual(len(encoded(actor)),8000)
        self.assertLessEqual(len(b'CI_FINANCIAL_ACTOR_DIAGNOSTIC '+encoded(actor)+b'\n'),8192)
        events=[dict(role=role,kind='ActorFailureBoundary',sequence=C.MAX_RECORDS,actor_elapsed_ns=C.ORIGINAL_NS,facts=dict(version=1,**failures[role])) for role in C.ROLES]
        observation=dict(version=1,site=max(C.OBSERVER_FAILURE_SITES,key=len),first_observed=dict(availability='Observed',read_index=2**31-1,since_first_successful_read_ns=C.ORIGINAL_NS,events=events))
        C.validate_observer_failure_diagnostic(observation)
        self.assertEqual(len(events),17);self.assertLessEqual(len(encoded(observation)),8000)
        self.assertLessEqual(len(b'CI_FINANCIAL_OBSERVER_FAILURE_DIAGNOSTIC '+encoded(observation)+b'\n'),8192)

if __name__=='__main__':unittest.main()
