"""Synthetic record fixtures test the oracle, NOT a native-flow pass."""
import copy
import importlib.util
import pathlib
import sys
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('financial_output_tested',ROOT/'ci-financial-output.py')
O=importlib.util.module_from_spec(spec);sys.modules[spec.name]=O;spec.loader.exec_module(O)
C=O.C

def observations():
    records=[];seq={r:0 for r in C.ROLES};pids={r:100+i for i,r in enumerate(C.ROLES)}
    def emit(role,kind,facts,when):
        seq[role]+=1;records.append(dict(schema=1,profile=C.PROFILE,role=role,
            sequence=seq[role],elapsed_ns=when,kind=kind,facts=facts))
    def birth(role,t):
        parent=C.PARENTS.get(role)
        emit(role,'Birth',dict(pid=pids[role],parent_pid=pids[parent] if parent else 99,parent_role=parent),t)
    birth('Coordinator',0);birth('Host',1);birth('Signer1',2);birth('Signer2',3)
    for role in C.ROLES[4:]:birth(role,4)
    t=10
    for index,owner in enumerate(('Signer1','Signer2'),1):
        for step in C.SIGNER_STEPS[:-3]:
            emit('Coordinator','SignerMilestone',dict(owner=owner,step=step),t);t+=1
        for w in [r for r in C.ROLES if r.startswith('Owner'+str(index))]:
            emit(w,'PurposeServing',{},t);t+=1;emit(w,'PurposeDisposed',{},t);t+=1
            emit(w,'PurposeClosed',{},t);t+=1
            emit('Coordinator','OwnedReap',dict(child=w,pid=pids[w],exit_code=0),t);t+=1
        emit('Host','HostMilestone',dict(step=f'Owner{index}AdmissionVerified'),t);t+=1
        emit('Coordinator','SignerMilestone',dict(owner=owner,step='SigningRetired'),t);t+=1
        emit('Host','HostMilestone',dict(step=f'Owner{index}SigningRetired'),t);t+=1
    emit('CompletedPair','PurposeServing',{},t);t+=1
    emit('Host','HostMilestone',dict(step='CompletedPairRetained'),t);t+=1
    for owner in ('Signer1','Signer2'):
        for step in ('ReturnPrepared','ReturnFinished'):
            emit('Coordinator','SignerMilestone',dict(owner=owner,step=step),t);t+=1
    for step in C.HOST_STEPS[-3:]:emit('Host','HostMilestone',dict(step=step),t);t+=1
    emit('Coordinator','NormalFinishAdmitted',{},t);t+=1
    emit('Coordinator','PtyHeld',{},t);t+=1
    for owner in ('Signer1','Signer2'):
        emit('Host','OwnedReap',dict(child=owner,pid=pids[owner],exit_code=0),t);t+=1
    emit('CompletedPair','PurposeDisposed',{},t);t+=1
    emit('CompletedPair','PurposeClosed',{},t);t+=1
    emit('Coordinator','OwnedReap',dict(child='CompletedPair',pid=pids['CompletedPair'],exit_code=0),t);t+=1
    emit('Coordinator','OwnedReap',dict(child='Host',pid=pids['Host'],exit_code=0),t);t+=1
    emit('Coordinator','PtyReleased',{},t);t+=1
    emit('Coordinator','NormalFinished',{},t)
    return records

class OracleTests(unittest.TestCase):
    def test_complete_shape_still_needs_external_build_and_cleanup(self):
        evidence=O.validate_completed(observations(),100,0)
        for build,cleanup in [(False,True),(True,False)]:
            with self.assertRaises(Exception):O.public_result(evidence,exact_build_verified=build,container_removed=cleanup)
    def test_every_owned_child_reap_required(self):
        for child in C.PARENTS:
            records=[r for r in observations() if not(r['kind']=='OwnedReap' and r['facts']['child']==child)]
            with self.assertRaises(Exception):O.validate_completed(records,100,0)
    def test_nonzero_root_or_worker_exit_never_passes(self):
        with self.assertRaises(Exception):O.validate_completed(observations(),100,1)
        records=observations();next(r for r in records if r['kind']=='OwnedReap')['facts']['exit_code']=1
        with self.assertRaises(Exception):O.validate_completed(records,100,0)
    def test_every_signer_and_host_step_required(self):
        original=observations()
        for index,r in enumerate(original):
            if r['kind'] in ('SignerMilestone','HostMilestone'):
                with self.assertRaises(Exception):O.validate_completed(original[:index]+original[index+1:],100,0)
    def test_pty_release_before_host_reap_rejected(self):
        records=observations();next(r for r in records if r['kind']=='PtyReleased')['elapsed_ns']=1
        with self.assertRaises(Exception):O.validate_completed(records,100,0)
    def test_replaced_pid_rejected(self):
        records=observations();next(r for r in records if r['kind']=='OwnedReap')['facts']['pid']=9999
        with self.assertRaises(Exception):O.validate_completed(records,100,0)

if __name__=='__main__':unittest.main()
