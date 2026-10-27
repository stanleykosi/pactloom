#!/usr/bin/env python3
"""Full native-flow oracle, not the old Witness-only UI qualification.

Validated observation shape alone is never a runtime pass. The outer exact
source/build gate must additionally establish actual process exit and container
removal. This module does not launch, stop, approve, or fabricate a product.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).parent
_spec = importlib.util.spec_from_file_location('ci_financial_contract',ROOT/'ci-financial-contract.py')
C = importlib.util.module_from_spec(_spec); sys.modules[_spec.name] = C; _spec.loader.exec_module(C)

class FullFlowEvidence:
    """Private validated evidence; repr intentionally excludes PIDs and records."""
    __slots__ = ('_token','_root_pid','_record_count')
    def __init__(self, token, root_pid, record_count):
        C.require(token is _TOKEN)
        self._token,self._root_pid,self._record_count=token,root_pid,record_count
    def __repr__(self):
        return '<FullFlowEvidence private>'
_TOKEN = object()

def validate_completed(records, actual_root_pid, actual_root_exit):
    C.require(type(records) is list and 0 < len(records) <= C.MAX_RECORDS,'record_limit')
    C.require(C.integer(actual_root_pid,2,2**31-1) and actual_root_exit == 0 and type(actual_root_exit) is int,'process')
    by_role={role:[] for role in C.ROLES}
    for record in records:
        C.validate_record(record)
        C.observer_failure_checked('FullOutputFailureRecord',C.require,record['kind'] != 'Failure','observer_failure')
        by_role[record['role']].append(record)
    births={}
    for role, entries in by_role.items():
        C.require(entries,'observer_missing')
        entries.sort(key=lambda e:e['sequence'])
        C.require([e['sequence'] for e in entries] == list(range(1,len(entries)+1)),'order')
        C.require(entries[0]['kind']=='Birth' and sum(e['kind']=='Birth' for e in entries)==1,'lineage')
        C.require(all(a['elapsed_ns']<=b['elapsed_ns'] for a,b in zip(entries,entries[1:])),'order')
        births[role]=entries[0]
    pids=[r['facts']['pid'] for r in births.values()]
    C.require(len(set(pids))==17 and births['Coordinator']['facts']['pid']==actual_root_pid,'lineage')
    for role,parent in C.PARENTS.items():
        C.require(births[role]['facts']['parent_pid']==births[parent]['facts']['pid'] and
                  births[parent]['elapsed_ns'] <= births[role]['elapsed_ns'],'lineage')
    milestones={}
    for owner in ('Signer1','Signer2'):
        entries=sorted((r for r in records if r['kind']=='SignerMilestone' and r['facts']['owner']==owner),
                       key=lambda r:r['elapsed_ns'])
        C.require(tuple(r['facts']['step'] for r in entries)==C.SIGNER_STEPS,'missing_evidence')
        milestones[owner]={r['facts']['step']:r['elapsed_ns'] for r in entries}
    host=[r for r in by_role['Host'] if r['kind']=='HostMilestone']
    C.require(tuple(r['facts']['step'] for r in host)==C.HOST_STEPS,'missing_evidence')
    host_times={r['facts']['step']:r['elapsed_ns'] for r in host}
    # The shared original installation is never opened concurrently by owners.
    C.require(milestones['Signer1']['SigningRetired'] <= milestones['Signer2']['EntryOpened'],'order')
    for owner in ('Signer1','Signer2'):
        C.require(milestones[owner]['SigningRetired'] <= host_times['CompletedPairRetained'] <=
                  milestones[owner]['ReturnPrepared'] < milestones[owner]['ReturnFinished'],'order')
    C.require(max(milestones[o]['ReturnFinished'] for o in milestones) <= host_times['BothReturnsIntaken'] <=
              host_times['TransactionSavedVerified'] <= host_times['NoDispatchSelected'],'order')
    reaps={}
    for r in records:
        if r['kind']=='OwnedReap':
            f=r['facts']; child=f['child']
            C.require(child not in reaps and f['pid']==births[child]['facts']['pid'] and f['exit_code']==0,'cleanup')
            reaps[child]=r
    C.require(set(reaps)==set(C.PARENTS),'cleanup')
    for role in C.WITNESSES:
        serving=[r for r in by_role[role] if r['kind']=='PurposeServing']
        C.require(len(serving)==1,'missing_evidence')
        disposed=[r for r in by_role[role] if r['kind']=='PurposeDisposed']
        closed=[r for r in by_role[role] if r['kind']=='PurposeClosed']
        C.require(len(disposed)==len(closed)==1,'cleanup')
        C.require(serving[0]['elapsed_ns'] <= disposed[0]['elapsed_ns'] <= closed[0]['elapsed_ns'] <= reaps[role]['elapsed_ns'],'cleanup')
    # Fixed tree can birth dormant W up front: service intervals, not process
    # lifetimes, must be serial on the same original installation.
    witness_order=C.ROLES[4:]
    for previous,current in zip(witness_order,witness_order[1:]):
        current_start=next(r for r in by_role[current] if r['kind']=='PurposeServing')
        C.require(reaps[previous]['elapsed_ns'] <= current_start['elapsed_ns'],'order')
    for index,owner in enumerate(('Signer1','Signer2'),1):
        C.require(reaps[f'Owner{index}FinancialSigning']['elapsed_ns'] <=
                  milestones[owner]['SigningRetired'] <= host_times[f'Owner{index}SigningRetired'],'order')
    pair_start=next(r for r in by_role['CompletedPair'] if r['kind']=='PurposeServing')
    C.require(host_times['Owner2SigningRetired'] <= pair_start['elapsed_ns'] <=
              host_times['CompletedPairRetained'],'order')
    root_events={}
    for name in ('NormalFinishAdmitted','NormalFinished','PtyHeld','PtyReleased'):
        matches=[r for r in by_role['Coordinator'] if r['kind']==name]
        C.require(len(matches)==1,'normal_finish'); root_events[name]=matches[0]['elapsed_ns']
    C.require(host_times['NoDispatchSelected'] <= root_events['NormalFinishAdmitted'] <= root_events['PtyHeld'], 'normal_finish')
    C.require(root_events['PtyHeld'] <= reaps['Host']['elapsed_ns'] <= root_events['PtyReleased'] <= root_events['NormalFinished'],'normal_finish')
    C.require(max(r['elapsed_ns'] for r in reaps.values()) <= root_events['NormalFinished'],'normal_finish')
    C.require(reaps['Signer1']['elapsed_ns'] <= reaps['Host']['elapsed_ns'] and
              reaps['Signer2']['elapsed_ns'] <= reaps['Host']['elapsed_ns'],'cleanup')
    return FullFlowEvidence(_TOKEN,actual_root_pid,len(records))

def public_result(evidence, *, exact_build_verified, container_removed):
    C.require(type(evidence) is FullFlowEvidence and evidence._token is _TOKEN,'missing_evidence')
    C.require(exact_build_verified is True and container_removed is True,'cleanup')
    # Never call a saved synthetic transaction public-chain settlement.
    return {'schema':C.SCHEMA,'profile':C.PROFILE,'status':'passed',
            'synthetic_full_native_verified':True,'public_chain_verified':False,
            'dispatch_attempted':False,'original_roles':17,'owned_child_reaps':16,
            'normal_finish_verified':True,'container_removed':True}

def failure(code):
    return {'schema':C.SCHEMA,'profile':C.PROFILE,'status':'failed',
            'code':code if code in C.ERRORS else 'contract',
            'synthetic_full_native_verified':False,'public_chain_verified':False}
