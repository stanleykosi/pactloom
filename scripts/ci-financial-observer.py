#!/usr/bin/env python3
"""Bounded private append-only observer collection; observations grant nothing."""
import copy
import importlib.util
import os
import pathlib
import re
import stat
import sys
import time

ROOT=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('financial_observer_contract',ROOT/'ci-financial-contract.py')
C=importlib.util.module_from_spec(spec);sys.modules[spec.name]=C;spec.loader.exec_module(C)
MAX_FILE_BYTES=32*1024*1024
MAX_TOTAL_BYTES=64*1024*1024

class ObserverFiles:
    def __init__(self,directory,deadline_ns,expected_profile=C.PROFILE):
        C.require(expected_profile in (C.PROFILE,C.EXTERNAL_PROFILE,C.SEMANTIC_PROFILE));self.expected_profile=expected_profile
        self.directory=pathlib.Path(directory);self.deadline_ns=deadline_ns
        self._files={};self._roles={};self._snapshot_generation=0
        self._semantic_active=None
        try:meta=self.directory.stat(follow_symlinks=False)
        except OSError:raise C.Rejected('observer_missing') from None
        C.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid==os.getuid() and
                  stat.S_IMODE(meta.st_mode)==0o700,'observer_missing')
        self._directory_identity=(meta.st_dev,meta.st_ino)
    def read(self,*,final=False):
        try:
            C.require(time.monotonic_ns()<self.deadline_ns,'deadline')
            return self._read(final)
        except C.Rejected:
            self._clear_host_view();raise
        except OSError:
            self._clear_host_view();raise C.Rejected('observer_failure') from None
    def _read(self,final):
        meta=self.directory.stat(follow_symlinks=False)
        C.require((meta.st_dev,meta.st_ino)==self._directory_identity,'observer_failure')
        names=sorted(p.name for p in self.directory.iterdir())
        C.require(len(names)<=17 and set(self._files)<=set(names),'record_limit')
        records=[];total=0
        for name in names:
            C.require(re.fullmatch('[1-9][0-9]{0,9}\\.jsonl',name) is not None,'record_shape')
            fd=os.open(self.directory/name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:
                before=os.fstat(stream.fileno())
                C.require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and
                          before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and
                          0<=before.st_size<=MAX_FILE_BYTES,'record_limit')
                raw=stream.read(MAX_FILE_BYTES+1);after=os.fstat(stream.fileno())
            total+=len(raw);C.require(len(raw)<=MAX_FILE_BYTES and total<=MAX_TOTAL_BYTES,'record_limit')
            identity=(before.st_dev,before.st_ino)
            prior=self._files.get(name,(identity,b''))
            C.require(prior[0]==identity and raw.startswith(prior[1]) and after.st_nlink==1,'replay')
            complete=raw[:raw.rfind(b'\n')+1]
            if final:C.require(raw==complete and len(raw)==before.st_size==after.st_size,'observer_failure')
            C.require(len(raw)-len(complete)<=C.MAX_RECORD_BYTES,'record_limit')
            entries=[]
            for line in complete.splitlines():
                C.require(len(records)+len(entries)<C.MAX_RECORDS,'record_limit')
                entry=C.validate_record(C.loads(line),self.expected_profile);entries.append(entry)
            if entries:
                role=entries[0]['role'];birth=entries[0]
                C.require(birth['kind']=='Birth' and birth['facts']['pid']==int(name[:-6]),'lineage')
                C.require(all(r['role']==role and r['sequence']==i for i,r in enumerate(entries,1)),'order')
                C.require(self._roles.get(role,name)==name,'lineage');self._roles[role]=name
            self._files[name]=(identity,complete);records.extend(entries)
        C.require(not final or len(self._roles)==17,'observer_missing')
        if self.expected_profile==C.SEMANTIC_PROFILE:self._join_host_views(records)
        return records
    def _clear_host_view(self):
        if self._semantic_active is not None:
            self._semantic_active['text'][:]=b'\0'*len(self._semantic_active['text'])
        self._semantic_active=None
    def _join_host_views(self,records):
        active=C.join_host_views(records)
        self._clear_host_view()
        if active is not None:
            self._semantic_active=copy.deepcopy(active)
            self._semantic_active['text']=bytearray(active['text'],'ascii')
    def host_view(self,snapshot):
        C.require(self.expected_profile==C.SEMANTIC_PROFILE and self._semantic_active is not None,'snapshot')
        view=self._semantic_active.copy();view['text']=bytes(view['text']).decode('ascii')
        C.match_host_view(snapshot,view)
        return view['text']
    def next_snapshot(self,deadline_ns):
        C.require(type(deadline_ns) is int and deadline_ns<=self.deadline_ns,'deadline')
        while time.monotonic_ns()<deadline_ns:
            records=self.read()
            C.require(not any(r['kind']=='Failure' for r in records),'observer_failure')
            candidates=[r['facts'] for r in records if r['kind']=='UiSnapshot' and
                        r['facts']['view_generation']>self._snapshot_generation]
            if candidates:
                result=max(candidates,key=lambda s:s['view_generation'])
                self._snapshot_generation=result['view_generation'];return result
            time.sleep(.01) # observation polling only; no input retry or deadline renewal.
        raise C.Rejected('deadline')
