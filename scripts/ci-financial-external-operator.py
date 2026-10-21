#!/usr/bin/env python3
"""Closed scheduling edge for the real separate pre-V3 native operator.

Signals stop/start existing genuine services only; no request/admission/result is
constructed here. Financial product authority still requires actual native UI.
"""
import importlib.util
import json
import os
import pathlib
import stat
import sys
ROOT=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('external_operator_contract',ROOT/'ci-financial-contract.py')
C=importlib.util.module_from_spec(spec);sys.modules[spec.name]=C;spec.loader.exec_module(C)
CONTROL=pathlib.Path('/ci-financial-control')
STEPS=('bootstrap_serving','bootstrap_drained','admission_committed','admission_drained',
       'audit_serving','audit_drained','transport_parked')

class ExternalOperator:
    def __init__(self):
        meta=CONTROL.stat(follow_symlinks=False)
        C.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid==os.getuid() and stat.S_IMODE(meta.st_mode)==0o700,'fixture_path')
        self._prefix=b'';self._identity=None;self.signaled=set();self.gates=[];self.events=[]
    def read(self,final=False):
        path=CONTROL/'external-witness-events.jsonl'
        if not path.exists():return []
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            meta=os.fstat(stream.fileno());C.require(stat.S_ISREG(meta.st_mode) and meta.st_uid==os.getuid() and
                meta.st_nlink==1 and stat.S_IMODE(meta.st_mode)==0o600 and meta.st_size<=32768,'fixture_path')
            raw=stream.read(32769)
        identity=(meta.st_dev,meta.st_ino)
        C.require((self._identity is None or self._identity==identity) and raw.startswith(self._prefix),'replay')
        self._identity=identity;complete=raw[:raw.rfind(b'\n')+1];self._prefix=complete
        C.require(not final or complete==raw,'record_shape')
        events=[C.loads(line,4096) for line in complete.splitlines()]
        C.require(len(events)<=14,'record_limit')
        for index,event in enumerate(events):
            C.exact(event,('version','owner','event'))
            C.require(event['version']==1 and event['owner']=='signer'+str(index//7+1) and event['event']==STEPS[index%7],'order')
        self.events=events;return events
    def parked(self,owner):
        self.read();return any(e['owner']==owner.lower() and e['event']=='transport_parked' for e in self.events)
    def signal(self,owner,kind,actual_record):
        key=(owner,kind)
        if key in self.signaled:return
        step='AdmissionAudited' if kind=='audit_stop' else 'SigningRetired'
        expected_owner=owner if kind=='audit_stop' else 'Signer1'
        C.require(actual_record['kind']=='SignerMilestone' and actual_record['facts']=={'owner':expected_owner,'step':step},'missing_evidence')
        name=f'v3-audit-stop-owner{owner[-1]}' if kind=='audit_stop' else 'v3-start-owner2'
        C.require(kind=='audit_stop' or (kind=='start' and owner=='Signer2'),'contract')
        data=b'stop\n' if kind=='audit_stop' else b'start\n'
        self.signaled.add(key)
        fd=os.open(CONTROL/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(data)
        self.gates.append({'owner':owner,'gate':kind,'role':actual_record['role'],'sequence':actual_record['sequence']})
    def financial_gate(self,owner,records):
        C.require(self.parked(owner),'missing_evidence')
        key=(owner,'financial_entry')
        if key in self.signaled:return
        snapshots=[r for r in records if r['role']=='Coordinator' and r['kind']=='UiSnapshot']
        C.require(snapshots,'missing_evidence');last=max(snapshots,key=lambda r:r['sequence'])
        self.signaled.add(key);self.gates.append({'owner':owner,'gate':'financial_entry','role':'Coordinator','sequence':last['sequence']})
    def evidence(self,cleanup,parent_pid,parent_exit):
        events=self.read(final=True);C.require(len(events)==14,'missing_evidence')
        return {'profile':C.EXTERNAL_PROFILE,'events':events,'gates':self.gates,'cleanup':cleanup,
                'actual_fixture_parent_pid':parent_pid,'actual_fixture_parent_exit':parent_exit}
