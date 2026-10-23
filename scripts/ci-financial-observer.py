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
FAILURE_DRAIN_NS=5_000_000_000

class ObserverFiles:
    def __init__(self,directory,deadline_ns,expected_profile=C.PROFILE):
        C.require(expected_profile in (C.PROFILE,C.EXTERNAL_PROFILE,C.SEMANTIC_PROFILE));self.expected_profile=expected_profile
        self.directory=pathlib.Path(directory);self.deadline_ns=deadline_ns
        self._files={};self._roles={};self._snapshot_generation=0
        self._semantic_active=None
        self._diagnostics=None
        self._failure_latched=False;self._failure_drain_deadline=None
        try:meta=self.directory.stat(follow_symlinks=False)
        except OSError:raise C.Rejected('observer_missing') from None
        C.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid==os.getuid() and
                  stat.S_IMODE(meta.st_mode)==0o700,'observer_missing')
        self._directory_identity=(meta.st_dev,meta.st_ino)
    def read(self,*,final=False,deadline_ns=None):
        try:
            bound=self.deadline_ns if deadline_ns is None else deadline_ns
            C.require(type(bound) is int and bound<=self.deadline_ns,'deadline')
            started=time.monotonic_ns();C.require(started<bound,'deadline')
            records=self._read(final)
            diagnostics=self._project_diagnostics(records)
            if diagnostics['timing']['availability']=='Observed':
                diagnostics['timing']['observer_remaining_ns']=self.deadline_ns-started
            try:C.validate_observation_timing_diagnostic(diagnostics['timing'])
            except C.Rejected:diagnostics['timing']=self._unavailable_timing()
            # Final check follows all collection/projection validation. Monotonic
            # time can only reduce the already-validated positive remainder.
            now=time.monotonic_ns();C.require(started<=now<bound,'deadline')
            if diagnostics['timing']['availability']=='Observed':
                diagnostics['timing']['observer_remaining_ns']=self.deadline_ns-now
            self._diagnostics=diagnostics
            return records
        except C.Rejected:
            self._clear_host_view();raise
        except OSError:
            self._clear_host_view();raise C.Rejected('observer_failure') from None
    def _read(self,final):
        meta=self.directory.stat(follow_symlinks=False)
        C.require((meta.st_dev,meta.st_ino)==self._directory_identity,'observer_failure')
        # Priority comes only from previously authenticated actor records.
        priority={self._roles.get('Coordinator'):0,self._roles.get('Host'):1}
        names=sorted((p.name for p in self.directory.iterdir()),key=lambda name:(priority.get(name,2),name))
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
        C.native_failure_sequence(records,self.expected_profile)
        C.validate_host_exit_cardinality(records)
        C.validate_actor_cardinality(records)
        if self.expected_profile==C.SEMANTIC_PROFILE:self._join_host_views(records)
        return records
    @staticmethod
    def _unavailable_timing():
        return dict(version=2,availability='Unavailable',observer_remaining_ns=None,
                    coordinator_last_elapsed_ns=None,last_phase=None,phase_observed_ns_counts=None,coordinator_milestone_elapsed_ns=None)
    def failure_diagnostics(self):
        """Bounded last-success copies only: no IO, clock reads, or proof use."""
        if self._diagnostics is None:
            return dict(progress=None,native=dict(version=1,availability='Unavailable',
                **{name:'Unobserved' for name in C.NATIVE_FAILURE_COMPONENTS}),timing=self._unavailable_timing(),host_exit=C.unavailable_host_exit_diagnostic(),actor=C.unavailable_actor_diagnostic())
        return copy.deepcopy(self._diagnostics)
    def _project_diagnostics(self,records):
        # Called only after the entire collection and semantic join validate.
        # Do not revalidate the unbounded history merely to derive summaries.
        progress=dict(version=1,signer_counts=[[0]*len(C.SIGNER_STEPS) for _ in range(2)],
            host_counts=[0]*len(C.HOST_STEPS),normal_counts=[0]*len(C.NORMAL_DIAGNOSTIC_STEPS),
            phase_counts=[0]*len(C.DIAGNOSTIC_PHASES))
        native=dict(version=1,availability='Unavailable',**{name:'Unobserved' for name in C.NATIVE_FAILURE_COMPONENTS})
        timing=dict(version=2,availability='Observed',observer_remaining_ns=None,
                    coordinator_last_elapsed_ns=None,last_phase=None,
                    phase_observed_ns_counts=[[[0,0] for _ in C.DIAGNOSTIC_PHASES] for _ in range(3)],
                    coordinator_milestone_elapsed_ns=[[None]*len(C.SIGNER_STEPS) for _ in range(2)])
        host_exit=C.unavailable_host_exit_diagnostic()
        actor=C.unavailable_actor_diagnostic()
        prior_elapsed=None;ordered=True
        for record in records:
            kind=record['kind'];facts=record['facts'];row=None
            if kind=='SignerMilestone':
                row=progress['signer_counts'][('Signer1','Signer2').index(facts['owner'])];index=C.SIGNER_STEPS.index(facts['step'])
            elif kind=='HostMilestone':row=progress['host_counts'];index=C.HOST_STEPS.index(facts['step'])
            elif kind=='UiSnapshot':row=progress['phase_counts'];index=C.DIAGNOSTIC_PHASES.index(facts['phase'])
            elif kind in C.NORMAL_DIAGNOSTIC_STEPS:row=progress['normal_counts'];index=C.NORMAL_DIAGNOSTIC_STEPS.index(kind)
            if row is not None:row[index]=min(2,row[index]+1)
            if kind in ('HostReapObservation','HostFailureBoundary'):
                part=host_exit['reap' if kind=='HostReapObservation' else 'foreground']
                part.update(copy.deepcopy({k:v for k,v in facts.items() if k!='version'}),availability='Observed')
            if kind=='ActorFailureBoundary':actor['actors'][record['role']]['failure']=copy.deepcopy({k:facts[k] for k in ('driver','listener','origin')})
            if kind=='ActorReapObservation':actor['actors'][facts['child']]['reap']=dict(parent=record['role'],**{k:facts[k] for k in ('context','exit_code','signal')})
            if record['role']!='Coordinator':continue
            elapsed=record['elapsed_ns'];timing['coordinator_last_elapsed_ns']=elapsed
            if prior_elapsed is not None and elapsed<prior_elapsed:ordered=False
            prior_elapsed=elapsed
            if kind=='SignerMilestone':
                row=timing['coordinator_milestone_elapsed_ns'][('Signer1','Signer2').index(facts['owner'])];index=C.SIGNER_STEPS.index(facts['step'])
                if row[index] is None:row[index]=elapsed # Coordinator observation offset, NOT actor issuance time.
            if kind=='NativeFailureBoundary':native.update(facts,availability='Observed')
            if kind=='UiSnapshot':
                phase=timing['last_phase'];identity={key:facts[key] for key in ('phase','subphase','owner')}
                if phase is None or any(phase[key]!=identity[key] for key in identity):
                    phase=dict(**identity,first_elapsed_ns=elapsed,last_elapsed_ns=elapsed,snapshot_count=0)
                    timing['last_phase']=phase
                cell=timing['phase_observed_ns_counts'][(None,'Signer1','Signer2').index(facts['owner'])][C.DIAGNOSTIC_PHASES.index(facts['phase'])]
                cell[0]+=elapsed-phase['last_elapsed_ns'];cell[1]+=1
                phase['last_elapsed_ns']=elapsed;phase['snapshot_count']+=1
        if not ordered:timing=self._unavailable_timing()
        return dict(progress=progress,native=native,timing=timing,host_exit=host_exit,actor=actor)
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
    def _drain_failure(self,deadline_ns,records):
        # Failure is already latched. This bounded observer-only exception never
        # returns to phase/input dispatch, probes a process, or renews a clock.
        # Host reap cannot prove independent Signer/Witness reporters finished.
        now=time.monotonic_ns()
        self._failure_drain_deadline=min(deadline_ns,self.deadline_ns,now+FAILURE_DRAIN_NS)
        bound=self._failure_drain_deadline
        try:
            while time.monotonic_ns()<bound:
                records=self.read(deadline_ns=bound)
                remaining=bound-time.monotonic_ns()
                if remaining<=0:return
                time.sleep(min(.01,remaining/1_000_000_000))
        except (C.Rejected,OSError):return # preserve original failure and last valid cache

    def next_snapshot(self,deadline_ns):
        C.require(not self._failure_latched,'observer_failure')
        C.require(type(deadline_ns) is int and deadline_ns<=self.deadline_ns,'deadline')
        while time.monotonic_ns()<deadline_ns:
            records=self.read(deadline_ns=deadline_ns)
            # Cache commits first; failure never returns to ordinary dispatch.
            if any(r['kind'] in ('Failure','NativeFailureBoundary','HostFailureBoundary','ActorFailureBoundary') for r in records):
                self._failure_latched=True
                if self.expected_profile==C.SEMANTIC_PROFILE:self._drain_failure(deadline_ns,records)
                raise C.Rejected('observer_failure')
            candidates=[r['facts'] for r in records if r['kind']=='UiSnapshot' and
                        r['facts']['view_generation']>self._snapshot_generation]
            if candidates:
                result=max(candidates,key=lambda s:s['view_generation'])
                self._snapshot_generation=result['view_generation'];return result
            time.sleep(.01) # observation polling only; no input retry or deadline renewal.
        raise C.Rejected('deadline')
