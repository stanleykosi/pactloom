#!/usr/bin/env python3
"""Actual native full-flow driver. No Origin calls, setters or forged result data."""
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
import time
ROOT=pathlib.Path(__file__).parent

def load(name):
    key=name.replace('-','_')
    if key in sys.modules:return sys.modules[key]
    spec=importlib.util.spec_from_file_location(key,ROOT/(name+'.py'))
    obj=importlib.util.module_from_spec(spec);sys.modules[key]=obj;spec.loader.exec_module(obj);return obj
S=load('ci-financial-scenario');C=S.C
H=load('ci-financial-host-context')

# Exact actual C branches, not success inferred from a label.
REVIEW={
 'V3PairReview':'FinalV3Pair','V3EnrollmentReview':'FinalV3Enrollment',
 'V3ManifestReview':'FinalV3Manifest','V3RedisclosureReadReview':'FinalV3RedisclosureRead',
 'V3RediscloseReview':'FinalV3Redisclose','V3PrepareReadReview':'FinalV3PrepareRead',
 'V3ReceiveReview':'FinalV3Receive','V3AdmitReadReview':'FinalV3AdmitRead',
 'V3AdmitReview':'ArmV3Admit','V3AdmitReady':'FinalV3Admit','V3AuditReview':'FinalV3Audit',
 'HistorySetupReview':'SetupHistory','HistoryReview':'ServeHistory','SetupReview':'Setup',
 'ActivateReadReview':'ActivateRead','ActivateReview':'ActivateArm','ActivateReady':'ActivateFinal',
 'WalletPrepareReview':'WalletPrepare','WalletObserveReview':'WalletObserve',
 'SignReadReview':'SignRead','SignExactReview':'SignExact',
 'ReturnReadReview':'ReturnRead','ReturnExactReview':'ReturnExact',
 'NormalFinishReview':'NormalFinish'}
READ_ONLY={'V3Review':'ConfirmV3','EntryReview':'EntryConfirm','ReadReview':'ReadConfirm',
           'ContinueReview':'ContinueConfirm'}
CONFIRM={'V3Confirm':'PasswordV3','EntryConfirm':'EnterPassword','ReadConfirm':'Read',
         'ContinueConfirm':'ArmContinue'}
DIRECT={'HistorySetupNeeded':'PrepareHistory','HistoryReady':'BeginContinue','SetupNeeded':'PrepareSetup',
        'SignedRetired':'ParkFinancial','ReturnCompleted':'ParkFinancial'}
FORMS={'V3Configuring':('v3','BeginV3'),'V3OwnerConfiguring':('owner','SelectV3Owner'),
       'FinancialSetupConfiguring':('financial','SelectFinancialSetup'),'Configuring':('witness','Begin')}
WITNESS_FIELDS=tuple('Field:'+name for name in ('Endpoint','ServerName','WitnessId',
 'PinnedServerCertificate','NetworkProfile','AccountId','OwnerCertificateDerHex','StorageKey',
 'ServerCertificate','ServerPrivateKey','TrustedClientRoot'))
# Actual draw_admission order: sibling review panes have NO vertical ordering
# relative to each other; both precede the two acknowledgements and two arms.
PAIRED_REVIEW_RANK={'SignerReviewBody':0,'WitnessReviewBody':0,
 'SignerReviewAcknowledgement':1,'WitnessReviewAcknowledgement':2,'ArmSigner':3,'ArmWitness':4}
SELECT=('ReviewV3Pair','ReviewV3Enrollment','ReviewV3Manifest','ReviewV3RedisclosureRead',
        'ReviewV3Redisclose','ConfigureV3Owner','ReviewV3PrepareRead','ReviewV3Receive',
        'ReviewV3AdmitRead','ReviewV3Admit','ReviewV3Audit','ConfigureFinancialSetup','Configure','ConfigureV3')
RESULT_PHASES=frozenset(('V3Held','V3Paired','V3Enrolled','V3ManifestAccepted','V3RedisclosurePrepared',
 'V3Redisclosed','V3OwnerSelected','V3Prepared','V3Received','V3AdmitReadRetained','V3AdmissionRetained','V3Audited'))

HOST_COMMANDS_INSTRUCTION='Select original reviewer 1 of 2 for its separate closed V3 admission.\n'

# Exact native public purpose text; this classifies navigation, never permission.
PAIR_PREPARATION_PURPOSE='Approve LOCAL exact-byte preparation for closed original delivery. Read and fully verify the selected retained proof and BOTH original materials, and retain one exact encoded private payload in local memory under the ORIGINAL absolute ceilings. No recipient disclosure, transport, signing, submission or admission is authorized.'
PAIR_CONFIRMATION_PURPOSE='Pair this exact original coordinated reviewer for independently approved receive/view. No native provider fallback or financial execution is authorized.'

HOST_STARTUP=('profile','workspace','password','financial_password','historical_approval',
              'principal','scope','shared','mode','origin','credential','session_approval',
              'session_commands_file')
HOST_STARTUP_MARKERS=(
 ('Existing original Host profile directory (absolute):','profile'),
 ('Existing original dispatcher workspace directory (absolute):','workspace'),
 ('Storage passphrase:','password'),
 ('Original primary financial passphrase:','financial_password'),
 ('Local application principal ID:','principal'),
 ('Scope choice: type SELECTED','scope'),
 ('Additional shared agreement IDs, comma-separated; blank for none:','shared'),
 ('Exact selected agreement IDs, comma-separated; blank grants no agreements:','unexpected'),
 ('Grant READ only, or PREPARE','mode'),
 ('Optional exact browser origin for this session','origin'),
 ('New private bootstrap credential file (absolute path','credential'),
 ('Exact immutable command keys JSON file','session_commands_file'),
 ('Exact coordinated reviewer selection JSON','unexpected'),
 ('Exact copied native continuation selector JSON file','unexpected'),
 ('Exact copied native AwaitingReturn result selector JSON file','unexpected'),
 ('Type APPROVE ','approval'))

class FullFlow:
    def __init__(self,controller,fixture,observer,ocr,operator=None):
        # Mandatory local safety configuration, not an overridable input action.
        S.K.Controller.enable_rendered_clicks(controller)
        self.operator=operator
        self.expected_profile=observer.expected_profile
        self.controller=controller;self.fixture=fixture;self.observer=observer;self.ocr=ocr
        if self.expected_profile==C.SEMANTIC_PROFILE:
            self.native=S.NativeScenario(controller,fixture,observer.next_snapshot,expected_profile=self.expected_profile,host_view=observer.host_view,wait_ceiling=self.startup_wait_ceiling)
        else:
            self.native=S.NativeScenario(controller,fixture,observer.next_snapshot)
        self.done=set();self.filled=set();self.scrolls={};self.actions=0;self.host_lines=0
        self._review_observed=None
        self.password_attempted=set();self.password_typed=set();self.password_pending=None
        self.last_ocr=0;self.ocr_delay=1_000_000_000;self.last_capture=None;self.challenges=set();self.host_paths=set()
        self.reviewer_index=0;self.continue_index=0;self.result_index=0
        self.pair_prompt=None;self.pair_navigation_submitted={}
        self.records=[];self.pending_host=None;self.location=None;self.pending_selection=None
        self.startup_index=0;self.startup_issued=None;self.pending_startup=None
        self.startup_waiting=False;self.startup_input_attempted=False
        self.commands_instruction_observed=False;self.commands_instruction_context=None
        self.startup_focus_seen=False;self.startup_focus_waits=0
        self.host_occurrences=H.HostOccurrences();self.pending_occurrence=None;self.host_rejection=None;self.host_stage='Unobserved';self.host_visibility_steps=0;self.host_deferred=None;self.host_ignored=None;self.host_prepared=None;self.host_coverage_context=None;self.host_coverage_steps=0
        self.input_checkpoint=None;self.last_phase=None;self.search_direction='up';self.search_geometry=None
        self.host_action='Unobserved';self.host_observed=None
        self.host_capture_outcome='Unobserved';self.host_capture_context=None
        self._startup_ceiling=None
        if self.expected_profile==C.SEMANTIC_PROFILE:
            self._startup_ceiling=min(self.fixture.deadline_ns,time.monotonic_ns()+C.ACTION_NS)
            S.K.Controller.install_wait_ceiling(controller,self.startup_wait_ceiling)
    def note_review_observation(self,s,*,seek=None,operation=None,boundary=None,anchor=None,point=None):
        # Best-effort projection only. No reads, clocks, input, or control checks.
        # The last validated review frame is retained across terminal/reset frames.
        try:
            if s['subphase']!='None' or s['phase'] not in C.REVIEW_ROUTES:return
            phase=s['phase'];owner=s['owner'];tags=C.REVIEW_ROUTES[phase]
            if owner not in ('Signer1','Signer2') and not(owner is None and phase=='NormalFinishReview'):return
            old=self._review_observed
            same=old is not None and old['owner']==owner and old['phase']==phase
            value=dict(version=3,semantics='LastValidatedReview',phase=phase,subphase='None',
                owner=owner,generation=s['view_generation'],widgets=[],
                seek_counts=[0 if t is None else self.scrolls.get((phase,'None','seek',t,owner),0) for t in tags],
                scroll_counts=[self.scrolls.get((phase,'None',t,o,d),0) for t,o,d in
                    (('ScrollRegion',None,'up'),('ScrollRegion',None,'down'),('ReviewBody',owner,'down'))],
                attempted=[False if t is None else self.used(s,t,owner) for t in tags[1:]],
                owed_wheel=(phase,'None','review-scroll-pending',tags[2],owner,'ReviewBody') in self.scrolls,
                last_seek=old['last_seek'] if same else 'None',
                operation=old['operation'] if same else 'None',boundary=old['boundary'] if same else 'None',
                operation_generation=old['operation_generation'] if same else None,
                anchor=old['anchor'] if same else 'None',point_inside=old['point_inside'] if same else None,
                costs=old['costs'] if same else {name:dict(attempted=0,returned=0,failed=0,total_ns=0,max_ns=0) for name in C.REVIEW_COST_BUCKETS},
                source_size=old['source_size'] if same else None)
            for tag in tags:
                w=self.find(s,tag,owner);value['widgets'].append([w is not None,False if w is None else w['enabled']])
            if seek is not None:value['last_seek']={tags[0]:'Body',tags[1]:'Ack',tags[2]:'Action'}.get(seek,'None')
            # Operation geometry belongs to this pre-effect observation, not a
            # later cached widget frame. Returned means call+wait returned only.
            if operation is not None:value.update(operation=operation,boundary=boundary,anchor=anchor,point_inside=None,operation_generation=s['view_generation'])
            if point is not None and anchor in ('Body','Outer','Ack','Action'):
                tag,who={'Body':('ReviewBody',owner),'Outer':('ScrollRegion',None),'Ack':('ReviewAcknowledgement',owner),'Action':(tags[2],owner)}[anchor]
                w=self.find(s,tag,who)
                if w is not None:
                    x0,y0,x1,y1=w['rect'];scale=s['pixels_per_point'];x,y=point
                    value['point_inside']=x0*scale<x<x1*scale and y0*scale<y<y1*scale
            self._review_observed=value
        except Exception:pass # Diagnostic failure cannot alter original inputs or failure.
    def _review_timed(self,bucket,call,*,snapshot_result=False,frame=None):
        # Observation only. Failure attribution is the LAST validated phase,
        # not proof of the failing native frame or acceptance. No call retries.
        observed=None
        try:
            observed=self._review_observed
            if observed is not None:
                identity=(observed['phase'],observed['subphase'],observed['owner'])
                if frame is not None and (frame['phase'],frame['subphase'],frame['owner'])!=identity:observed=None
        except Exception:observed=None
        started=None;result=None;returned=False
        if observed is not None:
            try:started=time.monotonic_ns()
            except Exception:pass
        try:
            result=call();returned=True;return result
        finally:
            try:
                if observed is not None and self._review_observed is observed:
                    if snapshot_result and returned and (result['phase'],result['subphase'],result['owner'])!=(observed['phase'],observed['subphase'],observed['owner']):
                        pass # Do not charge a cross-phase snapshot to either phase.
                    elif observed['costs'] is not None:
                        ended=time.monotonic_ns()
                        if type(started) is not int or type(ended) is not int or not 0<=started<=ended:raise ValueError()
                        elapsed=ended-started;row=observed['costs'][bucket]
                        updated=dict(attempted=row['attempted']+1,returned=row['returned']+int(returned),failed=row['failed']+int(not returned),total_ns=row['total_ns']+elapsed,max_ns=max(row['max_ns'],elapsed))
                        if not all(type(v) is int and 0<=v<=2**63-1 for v in updated.values()):raise ValueError()
                        observed['costs'][bucket]=updated
            except Exception:
                try:
                    if observed is not None:observed['costs']=None
                except Exception:pass
    def _note_review_source_size(self,frame):
        try:
            if self._review_observed is not None and (frame['phase'],frame['subphase'],frame['owner'])==(self._review_observed['phase'],self._review_observed['subphase'],self._review_observed['owner']):self._review_observed['source_size']=self.observer.collection_diagnostic()
        except Exception:
            try:
                if self._review_observed is not None:self._review_observed['source_size']=None
            except Exception:pass
    def review_diagnostic(self):
        # Deep copy only; not current-at-failure state or proof of input acceptance.
        return None if self._review_observed is None else json.loads(json.dumps(self._review_observed))
    def startup_wait_ceiling(self):
        # Read-only: observations, captures and navigation never renew this bound.
        return self._startup_ceiling
    def cache_host_observation(self,h):
        # Called only after existing validated snapshot/capture operations.
        # No text, paths, geometry or input values are retained here.
        view=h['view']
        coverage='Unavailable' if view is None else ('WholeRetained' if view['nonws']==h['nonws_end'] else 'TailSuffix')
        self.host_observed=(h['entry'],h['context_valid'],(h['revision'],h['nonws_end']),coverage)
    def host_diagnostic(self):
        # Failure-only projection of LAST VALIDATED observations, never current
        # native state or proof of acceptance. No new observation or I/O.
        cached=self.host_observed;pending=self.pending_occurrence
        observed_context=None if cached is None else cached[2]
        pending_context=('Unobserved' if cached is None else 'NoPending' if pending is None
                         else 'Same' if observed_context==(pending[2],pending[1]) else 'Changed')
        capture_context=('Unobserved' if observed_context is None or self.host_capture_context is None
                         else 'Same' if observed_context==self.host_capture_context else 'Changed')
        return dict(version=2,category=self.host_rejection or 'none',startup_stage=self.host_stage,
            attempted_lines=self.host_lines,boundary=dict(action=self.host_action,startup_index=self.startup_index,
                issued_index=-1 if self.startup_issued is None else self.startup_issued,
                pending_index=-1 if self.pending_startup is None else self.pending_startup,
                pending_host=self.pending_host is not None,input_attempted=self.startup_input_attempted,
                waiting=self.startup_waiting),observation=dict(entry='Unobserved' if cached is None else cached[0],
                context_valid=None if cached is None else cached[1],pending_context=pending_context,
                coverage='Unobserved' if cached is None else cached[3],capture_outcome=self.host_capture_outcome,
                capture_context=capture_context))
    def snapshot(self):
        self.fixture.check();snapshot=self._review_timed('NativeSnapshot',self.native.snapshot,snapshot_result=True)
        self.note_review_observation(snapshot)
        self.cache_host_observation(snapshot['host_observation'])
        # next_snapshot may observe later records while awaiting a fresh frame.
        # Refresh AFTER that read: Finished is not normal-completion proof, and
        # the exact native proof guard must not receive a pre-frame record set.
        # ObserverFiles retains append-only validation and the original deadline.
        self.records=self._review_timed('ProofRead',self.observer.read,frame=snapshot)
        self._note_review_source_size(snapshot)
        C.require(not any(r['kind']=='Failure' for r in self.records),'observer_failure')
        return snapshot
    @staticmethod
    def find(s,tag,owner):
        return next((w for w in s['widgets'] if w['tag']==tag and w['owner']==owner),None)
    def key(self,s,tag,owner):return (s['phase'],s['subphase'],tag,owner)
    def milestone(self,owner,step):
        return any(r['kind']=='SignerMilestone' and r['facts']=={'owner':owner,'step':step} for r in self.records)
    def host_milestone(self,step):
        return any(r['kind']=='HostMilestone' and r['facts']=={'step':step} for r in self.records)
    def financial_selection_ready(self,owner):
        # Scheduling only: the external audit service can be parked before H's
        # separately approved admission-status display completes. Keep Selecting
        # reachable for that Host prompt; never infer H completion from S audit.
        C.require(owner in ('Signer1','Signer2'),'input_phase')
        if not self.host_milestone('Owner'+owner[-1]+'AdmissionVerified'):return False
        if self.operator is not None:
            if not self.operator.parked(owner):return False
            self.operator.financial_gate(owner,self.records)
        return True
    def waiting_for_host_admission(self,s,owner):
        # Visible Host controls need no repeated navigation while H completes
        # its separately approved display. The outer loop still pumps every
        # fresh prompt and validates the unchanged original observation bound.
        h=s['host_observation']
        return (s['phase']=='Selecting' and s['subphase']=='None' and s['owner'] is None
                and owner in ('Signer1','Signer2') and self.host_startup_complete
                and self.milestone(owner,'AdmissionAudited')
                and not self.host_milestone('Owner'+owner[-1]+'AdmissionVerified')
                and s['focused'] and not(s['secret_input'] or s['host_input'])
                and h['context_valid'] and h['entry']=='Idle'
                and self.pending_host is None and self.host_prepared is None
                and all((w:=self.find(s,tag,None)) is not None and w['enabled']
                        for tag in ('HostOutput','BeginHostLine')))
    def current_owner(self):
        for owner in ('Signer1','Signer2'):
            if not self.milestone(owner,'SigningRetired'):return owner
        for owner in ('Signer1','Signer2'):
            if not self.milestone(owner,'ReturnFinished'):return owner
        return None
    def press(self,s,tag,owner,*,ordinal=None,paired_layout=False):
        key=self.key(s,tag,owner)+(ordinal,)
        C.require(key not in self.done,'replay')
        if paired_layout:
            C.require(s['phase']=='AdmissionReview' and s['subphase']=='None' and owner==s['owner']
                      and owner in ('Signer1','Signer2') and not(s['secret_input'] or s['host_input']),'input_phase')
        # Two real later frames before one effect. Repeated observations may wait;
        # an attempted effect is latched BEFORE send and never retried.
        try:
            latest=self._review_timed('StableFrames',lambda:self.native.stable(s['phase'],s['owner'],protected=s['secret_input'] or s['host_input'],**({'paired_layout':True} if paired_layout else {})),frame=s)
        except S.PairedLayoutChanged:
            # Only the explicitly opted-in pre-effect pair can defer. No latch,
            # input, navigation reset or deadline renewal precedes this return.
            if not paired_layout:raise
            return
        self.note_review_observation(latest)
        if tag=='PasswordSubmit' and s['phase'] in ('V3Password','Password'):
            self.password_guard(latest,s)
            C.require((s['phase'],owner) in self.password_typed,'replay')
        C.require(latest['subphase']==s['subphase'],'input_phase')
        w=self.find(latest,tag,owner);C.require(w is not None and w['enabled'],'input_disabled')
        if tag=='PasswordSubmit' and s['phase'] in ('V3Password','Password'):
            x,y=self.native.point(latest,tag,owner);a,b,c,d=w['rect'];scale=latest['pixels_per_point']
            C.require(a<x/scale<c and b<y/scale<d,'input_widget')
        self.done.add(key);self.actions+=1
        self.note_review_observation(latest)
        C.input_budget(self.actions<=512,'actions',self.actions)
        point=self.native.point(latest,tag,owner)
        self.note_review_observation(latest,operation='AckPress' if tag=='ReviewAcknowledgement' else 'ActionPress' if tag==C.REVIEW_ROUTES.get(s['phase'],(None,None,None))[2] else 'OtherPress',boundary='Requested',anchor='Ack' if tag=='ReviewAcknowledgement' else 'Action' if tag==C.REVIEW_ROUTES.get(s['phase'],(None,None,None))[2] else 'None',point=point)
        self.controller.click(*point);self.controller.wait_render_progress()
        self.note_review_observation(latest,operation='AckPress' if tag=='ReviewAcknowledgement' else 'ActionPress' if tag==C.REVIEW_ROUTES.get(s['phase'],(None,None,None))[2] else 'OtherPress',boundary='Returned',anchor='Ack' if tag=='ReviewAcknowledgement' else 'Action' if tag==C.REVIEW_ROUTES.get(s['phase'],(None,None,None))[2] else 'None',point=point)
    def selection_handoff_pending(self,s):
        if self.pending_selection is None:return False
        key=(s['phase'],s['subphase'],s['owner'])
        if key!=self.pending_selection:
            self.pending_selection=None;return False
        # A real outgoing selection was already sent. Its painted click frame
        # precedes the native intent tail; it grants no second action or retry.
        # Preserve restrictive input guards and wait only through fresh snapshots.
        h=s['host_observation']
        C.require(not(s['secret_input'] or s['host_input']) and h['context_valid']
                  and h['entry']=='Idle' and self.pending_host is None
                  and self.host_prepared is None,'input_phase')
        return True
    def used(self,s,tag,owner):return self.key(s,tag,owner)+(None,) in self.done
    def scroll(self,s,body,owner,direction='down'):
        w=self.find(s,body,owner)
        if w is None:return False
        key=(s['phase'],s['subphase'],body,owner,direction)
        count=self.scrolls.get(key,0);C.input_budget(count<128,'scroll',count);self.scrolls[key]=count+1
        self.note_review_observation(s)
        action=self.controller.scroll_up if direction=='up' else self.controller.scroll_down
        point=self.native.point(s,body,owner)
        if body=='ScrollRegion':
            x0,y0,x1,y1=w['rect'];scale=s['pixels_per_point']
            inners=[a['rect'] for a in s['widgets'] if a['tag'] in ('ReviewBody','SignerReviewBody','WitnessReviewBody','HostOutput','HostEditor','HostSubmit')]
            points=[(x1-3,y0+5+(y1-y0-10)*i/8) for i in range(9)]
            clear=next(((x,y) for x,y in points if not any(a<=x<=c and b<=y<=d for a,b,c,d in inners)),None)
            C.require(clear is not None,'input_widget');point=tuple(int(v*scale) for v in clear)
            if s['host_input']:
                x,y=(v/scale for v in point)
                C.require(x0<x<x1 and y0<y<y1 and not any(a<=x<=c and b<=y<=d for a,b,c,d in inners),'input_widget')
        operation='BodyDown' if body=='ReviewBody' and direction=='down' else 'OuterUp' if body=='ScrollRegion' and direction=='up' else 'OuterDown' if body=='ScrollRegion' else 'OtherScroll'
        anchor='Body' if operation=='BodyDown' else 'Outer' if operation in ('OuterUp','OuterDown') else 'None'
        self.note_review_observation(s,operation=operation,boundary='Requested',anchor=anchor,point=point)
        self._review_timed('WheelInput',lambda:action(*point),frame=s);self._review_timed('RenderWait',self.controller.wait_render_progress,frame=s)
        self.note_review_observation(s,operation=operation,boundary='Returned',anchor=anchor,point=point)
        return True
    def password_guard(self,latest,original):
        # Protected metadata only: no capture, Host input, or deadline renewal.
        C.require(latest['phase'] in ('V3Password','Password')
                  and latest['phase']==original['phase'] and latest['subphase']==original['subphase']=='None'
                  and latest['owner']==original['owner'] and latest['owner'] in ('Signer1','Signer2')
                  and latest['focused'] and latest['secret_input'] and not latest['host_input'],'input_phase')
        h=latest['host_observation'];old=original['host_observation']
        if self.password_pending is not None:
            C.require((latest['phase'],latest['owner'],h['revision'],h['nonws_end'])==self.password_pending,'input_phase')
        C.require(h['context_valid'] and h['entry']=='Idle' and h['view'] is None
                  and (h['revision'],h['nonws_end'])==(old['revision'],old['nonws_end'])
                  and self.pending_host is None and self.host_prepared is None,'input_phase')
    def password_seek(self,s,tag):
        C.require(tag in ('SourcePassword','PasswordSubmit'),'input_widget')
        self.password_guard(s,s)
        latest=self.native.stable(s['phase'],s['owner'],protected=True)
        self.password_guard(latest,s);owner=latest['owner']
        w=self.find(latest,tag,owner)
        if w is not None:
            C.require(w['enabled'],'input_disabled')
            x,y=self.native.point(latest,tag,owner);a,b,c,d=w['rect'];scale=latest['pixels_per_point']
            C.require(a<x/scale<c and b<y/scale<d,'input_widget')
            return latest
        key=(s['phase'],'None','seek',tag,owner);count=self.scrolls.get(key,0)
        self.scrolls[key]=count+1;C.require(count<64,'input_widget')
        order=('ReviewBody','SourcePassword','PasswordSubmit')
        anchors=[order.index(w['tag']) for w in latest['widgets'] if w['owner']==owner and w['tag'] in order]
        direction='up' if count<24 else 'down'
        if anchors:
            if order.index(tag)<min(anchors):direction='up'
            elif order.index(tag)>max(anchors):direction='down'
        outer=self.find(latest,'ScrollRegion',None)
        C.require(outer is not None and outer['enabled'],'input_widget')
        x0,y0,x1,y1=outer['rect'];scale=latest['pixels_per_point']
        excluded=[w['rect'] for w in latest['widgets'] if w['tag'] in
                  ('ReviewBody','SignerReviewBody','WitnessReviewBody','HostOutput','SourcePassword','PasswordSubmit')]
        point=None
        for y in (y0+5+(y1-y0-10)*i/8 for i in range(9)):
            px,py=int((x1-3)*scale),int(y*scale);x,y=px/scale,py/scale
            if x0<x<x1 and y0<y<y1 and not any(a<=x<=c and b<=y<=d for a,b,c,d in excluded):
                point=(px,py);break
        C.require(point is not None,'input_widget')
        key=(s['phase'],'None','ScrollRegion',None,direction);count=self.scrolls.get(key,0)
        C.input_budget(count<128,'scroll',count);self.scrolls[key]=count+1
        action=self.controller.scroll_up if direction=='up' else self.controller.scroll_down
        action(*point);self.controller.wait_render_progress()
        return None
    def password_step(self,s):
        self.password_guard(s,s)
        key=(s['phase'],s['owner'])
        if self.used(s,'PasswordSubmit',s['owner']):return
        if key not in self.password_typed:
            C.require(key not in self.password_attempted,'replay')
            field=self.password_seek(s,'SourcePassword')
            if field is None:return
            # Attempt is latched before acquiring or consuming even a synthetic secret.
            self.password_attempted.add(key)
            h=field['host_observation']
            self.password_pending=(field['phase'],field['owner'],h['revision'],h['nonws_end'])
            secret=self.fixture.secret('source')
            try:
                self.native.protected_input(s['phase'],s['owner'],'SourcePassword',secret,
                                            source_context=(h['revision'],h['nonws_end']))
            finally:secret.wipe()
            self.password_typed.add(key)
            s=self.snapshot();self.password_guard(s,field)
        submit=self.password_seek(s,'PasswordSubmit')
        if submit is not None:
            self.press(submit,'PasswordSubmit',submit['owner'])
            self.password_pending=None
    def review_seek(self,s,tag,owner,action,ack,body):
        # These existing Writer subflows render the same body/consent/action
        # order. Opt in only their exact native route; never infer completion.
        if s['phase']=='WriterFlow' and s['subphase'] in ('SetupNeeded','SetupReview','ServiceReview','ReadReview','AcquireReview'):
            order=('ReviewBody',None if s['subphase']=='SetupNeeded' else 'ReviewAcknowledgement','WriterAction')
            if (body,ack,action)==order:
                return self._seek(s,tag,owner,tuple(t for t in order if t is not None))
        order=C.REVIEW_ROUTES.get(s['phase'])
        if s['subphase']=='None' and order==(body,ack,action):
            return self._seek(s,tag,owner,tuple(t for t in order if t is not None))
        return self.seek(s,tag,owner) # Paired/subflow/nonreview policy is unchanged.
    def seek(self,s,tag,owner):
        order=('ReviewBody','ReviewAcknowledgement','ArmV3Admit') if s['phase']=='V3AdmitReview' and s['subphase']=='None' else None
        return self._seek(s,tag,owner,order)
    def _seek(self,s,tag,owner,order):
        self.note_review_observation(s,seek=tag)
        if self.find(s,tag,owner) is not None:return True
        # Ordinary native wheel search only; no click on an invented rectangle.
        key=(s['phase'],s['subphase'],'seek',tag,owner)
        count=self.scrolls.get(key,0);self.scrolls[key]=count+1
        self.note_review_observation(s,seek=tag)
        C.require(count<64,'input_widget')
        direction='up' if count<24 else 'down'
        if s['phase']=='AdmissionReview' and s['subphase']=='None' and tag in PAIRED_REVIEW_RANK:
            C.require(owner==s['owner'] and owner in ('Signer1','Signer2') and s['focused']
                      and not(s['secret_input'] or s['host_input']),'input_phase')
            try:latest=self.native.stable(s['phase'],s['owner'],paired_layout=True)
            except S.PairedLayoutChanged:
                # Pre-effect layout deferral consumes this original seek count;
                # it cannot reset navigation or extend any native/fixture clock.
                return False
            h=latest['host_observation'];old=s['host_observation']
            C.require(latest['subphase']=='None' and latest['owner']==owner,'input_phase')
            if (not h['context_valid'] or h['entry']!='Idle'
                    or self.pending_host is not None or self.host_prepared is not None
                    or (h['revision'],h['nonws_end'])!=(old['revision'],old['nonws_end'])):return False
            if self.find(latest,tag,owner) is not None:return False
            target=PAIRED_REVIEW_RANK[tag]
            anchors=[PAIRED_REVIEW_RANK[w['tag']] for w in latest['widgets']
                     if w['owner']==owner and w['tag'] in PAIRED_REVIEW_RANK
                     and PAIRED_REVIEW_RANK[w['tag']]!=target]
            if anchors:
                if target<min(anchors):direction='up'
                elif target>max(anchors):direction='down'
            # Unknown/equal-level/conflicting anchors retain the original finite
            # fallback. Only fresh, strictly one-sided anchors change direction.
            self.scroll(latest,'ScrollRegion',None,direction)
            return False
        if order is not None and tag in order:
            # Exact native order is body, optional acknowledgement, action. An owed body
            # scroll must not turn downward after repeated action/body trips.
            latest=self._review_timed('StableFrames',lambda:self.native.stable(s['phase'],s['owner']),frame=s)
            self.note_review_observation(latest,seek=tag)
            h=latest['host_observation'];old=s['host_observation']
            C.require(latest['subphase']==s['subphase'] and owner==latest['owner']
                      and (owner in ('Signer1','Signer2') or (owner is None and s['phase']=='NormalFinishReview')),'input_phase')
            if (not h['context_valid'] or h['entry']!='Idle'
                    or self.pending_host is not None or self.host_prepared is not None
                    or (h['revision'],h['nonws_end'])!=(old['revision'],old['nonws_end'])):return False
            if self.find(latest,tag,owner) is not None:return False
            anchors=[w for w in latest['widgets'] if w['owner']==owner and w['tag'] in order]
            if anchors:
                positions=[order.index(w['tag']) for w in anchors]
                target=order.index(tag)
                if target<min(positions):direction='up'
                elif target>max(positions):direction='down'
            self.scroll(latest,'ScrollRegion',None,direction)
            return False
        if s['phase']=='Configuring' and s['subphase']=='None' and tag in WITNESS_FIELDS:
            # Witness selectors live in their own native ScrollArea. Wheel over
            # an actual visible field, never an invented inner-region rectangle.
            latest=self.native.stable(s['phase'],s['owner'])
            h=latest['host_observation'];old=s['host_observation']
            C.require(latest['subphase']==s['subphase'] and owner==latest['owner']
                      and owner in ('Signer1','Signer2'),'input_phase')
            if (not h['context_valid'] or h['entry']!='Idle'
                    or self.pending_host is not None or self.host_prepared is not None
                    or (h['revision'],h['nonws_end'])!=(old['revision'],old['nonws_end'])):return False
            if self.find(latest,tag,owner) is not None:return False
            anchors=[]
            for w in latest['widgets']:
                if w['tag'] not in WITNESS_FIELDS or w['owner']!=owner or not w['enabled']:continue
                x0,y0,x1,y1=w['rect'];scale=latest['pixels_per_point']
                x,y=self.native.point(latest,w['tag'],owner)
                if x0*scale<x<x1*scale and y0*scale<y<y1*scale:anchors.append(w)
            anchor=max(anchors,key=lambda w:(w['rect'][2]-w['rect'][0])*(w['rect'][3]-w['rect'][1]),default=None)
            if anchor is not None:
                # Exact native declaration order tells which side of the visible
                # selector lies the clipped target; do not restart an up-sweep
                # for each of the eleven fields and consume the shared budget.
                direction='down' if WITNESS_FIELDS.index(tag)>WITNESS_FIELDS.index(anchor['tag']) else 'up'
                # Charge the original shared outer-navigation counter even
                # though the actual wheel pointer targets this inner control.
                key=(latest['phase'],latest['subphase'],'ScrollRegion',None,direction)
                steps=self.scrolls.get(key,0);C.input_budget(steps<128,'scroll',steps)
                self.scrolls[key]=steps+1
                wheel=self.controller.scroll_up if direction=='up' else self.controller.scroll_down
                wheel(*self.native.point(latest,anchor['tag'],owner));self.controller.wait_render_progress()
            elif not any(w['tag'] in WITNESS_FIELDS and w['owner']==owner for w in latest['widgets']):
                self.scroll(latest,'ScrollRegion',None,direction)
            # Visible but disabled/subpixel-only selectors do not authorize a wheel.
            return False
        self.scroll(s,'ScrollRegion',None,direction);return False
    def idle_scan(self,s):
        # Clipped/tagged geometry can stay identical while untagged content
        # moves. Never treat that equality as proof of a scroll boundary.
        # One finite up-then-down sweep per actual phase/subphase/owner; the
        # existing native scroll/input/deadline guards remain authoritative.
        key=(s['phase'],s['subphase'],'idle_sweep',s['owner'])
        count=self.scrolls.get(key,0);C.input_budget(count<64,'idle_sweep',count)
        self.scrolls[key]=count+1
        return self.scroll(s,'ScrollRegion',None,'up' if count<8 else 'down')
    def initial_pair_navigation_target(self,s):
        target=self.current_owner();h=s['host_observation']
        if (s['phase']=='Selecting' and s['subphase']=='None' and s['owner'] is None
                and target in ('Signer1','Signer2') and self.host_startup_complete
                and self.pending_host is None and self.host_prepared is None
                and s['focused'] and not(s['secret_input'] or s['host_input'])
                and h['context_valid'] and h['entry']=='Idle'
                and self.milestone(target,'EntryOpened') and not self.milestone(target,'Paired')):
            return target
        return None
    def initial_pair_purpose(self,text,observed,occurrence,suffix):
        # A generic APPROVE tail is insufficient: the immediately preceding
        # complete purpose must belong to this fresh captured occurrence too.
        if not H.APPROVAL.fullmatch(suffix):return None
        for kind,detail in (('Preparation',PAIR_PREPARATION_PURPOSE),('Pair',PAIR_CONFIRMATION_PURPOSE)):
            match=re.search(H._literal_pattern(detail)+r'[ \t\r\n\f\v]*'+re.escape(suffix)+r'\Z',text)
            if match is not None:
                size=H.count(match.group(0));start=observed['nonws_end']-size
                if (0<size<=observed['view']['nonws'] and start>=self.host_occurrences.frontier
                        and occurrence[1:]==(observed['nonws_end'],observed['revision'])):
                    return kind
        return None
    def reserve_initial_pair_navigation(self,s,target):
        if target!=self.initial_pair_navigation_target(s) or target is None or target in self.pair_navigation_submitted:return False
        # Keep the real Host pane reachable without spending/resetting idle64.
        # After exact Pair submission H blocks on its original response bound;
        # the existing sweep can then find a later/clipped native Pair control.
        for tag in ('HostOutput','BeginHostLine'):
            if self.find(s,tag,None) is None:
                self.seek(s,tag,None);return True
        return True
    def wait_initial_pair_after_sweep(self,s,target):
        # Initial Pair is issued asynchronously by the original Host/Signer
        # after EntryOpened. A finite navigation budget is not its native clock.
        # Once the same 64 gestures are spent, permit ONLY fresh observations;
        # never renew navigation, select the other role, or infer Pair readiness.
        key=(s['phase'],s['subphase'],'idle_sweep',s['owner'])
        if not (s['phase']=='Selecting' and s['subphase']=='None' and s['owner'] is None
                and target in ('Signer1','Signer2') and self.host_startup_complete
                and self.pending_host is None and self.host_prepared is None
                and s['focused'] and not(s['secret_input'] or s['host_input'])
                and s['host_observation']['context_valid'] and s['host_observation']['entry']=='Idle'
                and self.milestone(target,'EntryOpened') and not self.milestone(target,'Paired')
                and self.scrolls.get(key,0)==64):return False
        # Only the existing snapshot reader waits; no controller command is sent.
        # Its fresh-generation guard and every original deadline still apply.
        # The outer loop continues Host pumping/operator service and scans actual
        # enabled actions BEFORE returning here; no action is synthesized here.
        return True

    def field(self,s,tag,owner,value):
        key=(s['phase'],tag,owner)
        if key in self.filled:return True
        if not self.seek(s,tag,owner):return False
        S.K._ascii_events(value)
        latest=self.native.stable(s['phase'],s['owner'])
        self.filled.add(key)
        self.controller.click(*self.native.point(latest,tag,owner));self.controller.clear_field()
        self.controller.type_ascii(value);return False
    def review(self,s,action,owner,*,ack='ReviewAcknowledgement',body='ReviewBody'):
        self.note_review_observation(s)
        if s['secret_input'] or s['host_input']:return False
        if self.used(s,action,owner):return False
        checkbox=self.find(s,ack,owner) if ack else None
        if ack and not self.used(s,ack,owner):
            if checkbox is not None and checkbox['enabled']:
                self.press(s,ack,owner);return True
            if self.review_seek(s,ack,owner,action,ack,body):return False
            return True
        pending=(s['phase'],s['subphase'],'review-scroll-pending',action,owner,body)
        if pending not in self.scrolls:
            button=self.find(s,action,owner)
            if button is not None and button['enabled']:
                self.press(s,action,owner);return True
            if button is None:return not self.review_seek(s,action,owner,action,ack,body)
            self.scrolls[pending]=1
            self.note_review_observation(s)
        # Remember only an owed ordinary wheel gesture, not read completion.
        # The disabled action and review body may occupy disjoint viewports.
        # Re-seek the action only after the actual body scroll has completed.
        observed_body=self.find(s,body,owner)
        if observed_body is not None and not observed_body['enabled']:return False
        if self.scroll(s,body,owner):
            del self.scrolls[pending]
            self.note_review_observation(s)
            return True
        return not self.review_seek(s,body,owner,action,ack,body)
    def paired_admission(self,s,owner):
        # Native paired_approved requires BOTH complete reviews and BOTH
        # acknowledgements before EITHER separate one-use arm is enabled.
        sides=(('SignerReviewAcknowledgement','SignerReviewBody'),
               ('WitnessReviewAcknowledgement','WitnessReviewBody'))
        for ack,body in sides:
            if not self.used(s,ack,owner):
                checkbox=self.find(s,ack,owner)
                if checkbox is not None and checkbox['enabled']:self.press(s,ack,owner,paired_layout=True)
                else:self.seek(s,ack,owner)
                return
        for action in ('ArmSigner','ArmWitness'):
            if self.used(s,action,owner):continue
            pending=(s['phase'],s['subphase'],'paired-review-pending',owner,action)
            key=(s['phase'],s['subphase'],'paired-review',owner)
            if pending not in self.scrolls:
                button=self.find(s,action,owner)
                if button is None:self.seek(s,action,owner);return
                if button['enabled']:self.press(s,action,owner,paired_layout=True);return
                turn=self.scrolls.get(key,0);C.input_budget(turn<256,'paired_review',turn)
                self.scrolls[pending]=turn
            # Complete this ordinary body-wheel turn before re-seeking the arm:
            # the button and body need not fit in the same actual viewport.
            # This remembers work, never read completion or approval authority.
            turn=self.scrolls[pending];body=sides[turn%2][1]
            if self.scroll(s,body,owner):
                self.scrolls[key]=turn+1;del self.scrolls[pending]
            else:self.seek(s,body,owner)
            return

    def save_selector(self,s,owner,kind):
        tag='Field:'+('ContinueSelectorPath' if kind=='continue' else 'ResultSelectorPath')
        action='SaveContinuationSelector' if kind=='continue' else 'SaveResultSelector'
        path=self.fixture.source_path(owner,'continuation_output_file' if kind=='continue' else 'result_output_file')
        if pathlib.Path(path).exists():
            self.fixture.source_path(owner,'continuation_output_file' if kind=='continue' else 'result_output_file',must_exist=True)
            return False
        if self.find(s,tag,owner) is None:
            expected=(kind=='result' and s['phase']=='SignCommitted') or (kind=='continue' and s['phase']=='SetupNeeded')
            if expected and s['owner']==owner:self.seek(s,tag,owner);return True
            return False
        if not self.field(s,tag,owner,path):return True
        if self.find(s,action,owner) and self.find(s,action,owner)['enabled'] and not self.used(s,action,owner):
            self.press(s,action,owner);return True
        return False
    @property
    def host_startup_complete(self):
        # Local scheduling guard only, never native approval/completion evidence.
        return (self.startup_index==len(HOST_STARTUP) and not self.startup_waiting
                and self.pending_startup is None
                and self.startup_issued is None
                and (self.expected_profile!=C.SEMANTIC_PROFILE or self.commands_instruction_observed))

    def observe_commands_instruction(self,s):
        """Passive commands-consumption discriminator; not an input or proof.

        Native asks for the path without a newline, then emits this exact message
        before waiting for the first V3 endpoint. Keep the original final-slot
        deadline until that actual rendered suffix is observed. No ledger grant,
        retry, normalization, private fixture text or direct process read.
        """
        C.require(self.expected_profile==C.SEMANTIC_PROFILE and
                  self.startup_index==len(HOST_STARTUP) and not self.startup_waiting and
                  self.pending_host is None and self.pending_startup is None and
                  self.startup_issued is None,'input_phase')
        C.require(self._startup_ceiling is not None and time.monotonic_ns()<self._startup_ceiling,'deadline')
        C.require(s['focused'] and not(s['host_input'] or s['secret_input']),'input_phase')
        h=s['host_observation']
        if not h['context_valid'] or h['entry']!='Idle':return False
        if self.find(s,'HostOutput',None) is None:return False
        if h['view'] is None:return self.seek_host_tail(s)
        if time.monotonic_ns()-self.last_ocr<self.ocr_delay:return False
        self.last_ocr=time.monotonic_ns();self.host_action='NoPending'
        try:text,observed=self.native.capture_host(s['phase'],s['owner'],self.ocr)
        except S.HostObservationChanged:return True # Fresh outer snapshot only.
        except C.Rejected:
            self.host_rejection='capture_guard';self.host_capture_outcome='capture_guard'
            self.host_capture_context=None;raise
        self.cache_host_observation(observed)
        self.host_capture_context=(observed['revision'],observed['nonws_end'])
        C.snapshot_checked('HostContext',C.require,type(text) is str and text.isascii() and len(text)<=8192 and
                  H.count(text)==observed['view']['nonws'],'snapshot')
        C.snapshot_checked('HostContext',C.require,observed['revision']>=self.host_occurrences.last_revision and
                  observed['nonws_end']>=self.host_occurrences.last_end,'snapshot')
        if text.endswith(HOST_COMMANDS_INSTRUCTION):
            start=observed['nonws_end']-H.count(HOST_COMMANDS_INSTRUCTION)
            C.require(start>=self.host_occurrences.frontier and
                      observed['nonws_end']>self.host_occurrences.frontier,'input_phase')
            # A blocking read must not resurrect an expired final-slot ceiling.
            C.require(time.monotonic_ns()<self._startup_ceiling,'deadline')
            self.commands_instruction_observed=True;self.host_stage='Operational'
            self.commands_instruction_context=(observed['revision'],observed['nonws_end'])
            self.host_capture_outcome='Accepted';self.host_rejection=None
            self.host_coverage_context=None;self._startup_ceiling=None
            return True # Dispatch only from a fresh main-loop observation.
        self.host_capture_outcome='host_capture_grammar';self.host_rejection='host_capture_grammar'
        if observed['view']['nonws']<observed['nonws_end']:
            context=(observed['revision'],observed['nonws_end'])
            if self.host_coverage_context!=context:self.host_coverage_steps=0
            self.host_coverage_context=context
            return self.seek_host_coverage(s)
        return False

    def startup_host_line(self,text):
        """Only the next native startup prompt may consume one exact response.

        Merely recognizing a prompt never advances this sequence: actual guarded
        HostSubmit must return first. Empty replies are deliberate native lines.
        No source/reviewer input can skip the original Host enrollment gates.
        """
        positions=[(text.rfind(marker),kind) for marker,kind in HOST_STARTUP_MARKERS if marker in text]
        if not positions:return None
        position,kind=max(positions);tail=text[position:]
        expected=HOST_STARTUP[self.startup_index];challenge=None
        if kind=='approval':
            matches=re.findall(r'Type (APPROVE [0-9a-f]{16}) to approve this exact operation,',tail)
            if not matches:return None
            challenge=matches[-1]
            if challenge in self.challenges:return None
            C.require(expected in ('historical_approval','session_approval'),'input_phase')
        else:
            C.require(kind in HOST_STARTUP,'input_phase')
            index=HOST_STARTUP.index(kind)
            if index<self.startup_index:return None
            C.require(index==self.startup_index,'input_phase')
        if self.startup_issued is not None:return None
        self.fixture.validate_host_startup()
        if expected in ('password','financial_password'):line=('secret',None)
        elif challenge is not None:line=('public',challenge)
        else:line=('public',self.fixture.host_startup_value(expected))
        self.startup_issued=self.startup_index # latch BEFORE input; never retry.
        if challenge is not None:self.challenges.add(challenge)
        return line

    def startup_submitted(self):
        if self.expected_profile==C.SEMANTIC_PROFILE:
            now=time.monotonic_ns()
            C.require(self._startup_ceiling is not None and now<self._startup_ceiling,'deadline')
        C.require(self.pending_startup==self.startup_index==self.startup_issued,'input_phase')
        self.host_paths.add(HOST_STARTUP[self.startup_index])
        self.startup_index+=1;self.startup_issued=None;self.pending_startup=None
        self.startup_input_attempted=False;self.startup_waiting=True
        if self.expected_profile==C.SEMANTIC_PROFILE and self.startup_index<len(HOST_STARTUP):
            self._startup_ceiling=min(self.fixture.deadline_ns,now+C.ACTION_NS)

    def expected_host_line(self,rendered):
        # OCR whitespace wrapping may vary; characters/challenge are never repaired.
        text=' '.join(rendered.split())
        if self.startup_index<len(HOST_STARTUP):return self.startup_host_line(text)
        markers=('Existing original Host profile directory (absolute):','Existing original dispatcher workspace directory (absolute):','Exact immutable command keys JSON file','Storage passphrase:','Exact coordinated reviewer selection JSON','Exact copied native continuation selector JSON file','Exact copied native AwaitingReturn result selector JSON file','Type APPROVE ')
        positions=[text.rfind(marker) for marker in markers if marker in text]
        if positions:text=text[max(positions):]
        prompts=(('Existing original Host profile directory (absolute):','profile'),
                 ('Existing original dispatcher workspace directory (absolute):','workspace'),
                 ('Exact immutable command keys JSON file','session_commands_file'))
        for prompt,key in prompts:
            if prompt in text and key not in self.host_paths:
                self.host_paths.add(key);return ('public',self.fixture.top_path(key))
        if 'Storage passphrase:' in text and 'password' not in self.host_paths:
            self.host_paths.add('password');return ('secret',None)
        if 'Exact coordinated reviewer selection JSON' in text:
            if self.reviewer_index>=2:return None
            if self.reviewer_index==1 and not self.host_milestone('Owner1SigningRetired'):
                # Deferred readiness is not consumption of the rendered prompt.
                return None
            owner='Signer'+str(self.reviewer_index+1)
            # Native Host.read_json reads an absolute artifact path, not JSON
            # entered into the terminal. Creation is exclusive and never retried.
            path=self.fixture.reviewer_selection_path(owner)
            self.reviewer_index+=1
            return ('public',path)
        for prompt,kind,counter in (
          ('Exact copied native continuation selector JSON file','continuation_output_file','continue_index'),
          ('Exact copied native AwaitingReturn result selector JSON file','result_output_file','result_index')):
            if prompt in text:
                index=getattr(self,counter)
                if index>=2:return None
                if index==1 and not self.host_milestone('Owner1SigningRetired'):
                    return None
                owner='Signer'+str(index+1);path=self.fixture.source_path(owner,kind)
                if not pathlib.Path(path).exists():return None
                self.fixture.source_path(owner,kind,must_exist=True);setattr(self,counter,index+1)
                return ('public',path)
        matches=re.findall(r'Type (APPROVE [0-9a-f]{16}) to approve this exact operation,',text)
        if matches:
            challenge=matches[-1]
            if challenge in self.challenges:return None
            C.input_budget(len(self.challenges)<96,'challenges',len(self.challenges));self.challenges.add(challenge)
            return ('public',challenge)
        return None
    def seek_host_tail(self,s):
        # Explore both nested and outer visibility, never infer a tail from
        # motion, equality, time or a wheel count. Only native metadata admits.
        C.require(not s['host_input'] and not s['secret_input'],'sensitive_capture')
        C.input_budget(self.host_visibility_steps<128,'host_tail',self.host_visibility_steps)
        step=self.host_visibility_steps;self.host_visibility_steps+=1
        latest=self.native.stable(s['phase'],s['owner'])
        if step%2==0:return self.scroll(latest,'HostOutput',None,'down')
        return self.scroll(latest,'ScrollRegion',None,'up' if step//2<8 else 'down')

    def seek_host_coverage(self,s):
        if self.host_coverage_steps>=16:
            # Incidental informational endings must not indefinitely steal a
            # Source review. This is exhaustion, NOT proof of Host completeness.
            return False
        coverage_step=self.host_coverage_steps;self.host_coverage_steps+=1
        C.require(not s['host_input'] and not s['secret_input'],'sensitive_capture')
        C.input_budget(self.host_visibility_steps<128,'host_coverage',self.host_visibility_steps)
        step=self.host_visibility_steps;self.host_visibility_steps+=1
        latest=self.native.stable(s['phase'],s['owner'])
        return self.scroll(latest,'ScrollRegion',None,'up' if coverage_step<8 else 'down')

    def seek_waiting_host_control(self,s,tag):
        # Navigation only in the two native Host-approval waiting phases. Never
        # turn new geometry or a changed prompt into approval/capture authority.
        if s['phase'] not in ('V3Receiving','ReturnReading'):return False
        latest=self.native.stable(s['phase'],s['owner'])
        h=latest['host_observation'];old=s['host_observation']
        if (latest['subphase']!=s['subphase'] or not latest['focused']
                or latest['secret_input'] or latest['host_input']
                or self.pending_host is not None or self.host_prepared is not None
                or not h['context_valid'] or h['entry']!='Idle'
                or (h['revision'],h['nonws_end'])!=(old['revision'],old['nonws_end'])
                or h['nonws_end']<=self.host_occurrences.frontier):return True
        button=self.find(latest,'BeginHostLine',None)
        if button is not None and not button['enabled']:return True
        if self.find(latest,tag,None) is None:self.seek(latest,tag,None)
        # Even if the target appeared, re-enter the pump on a new outer frame.
        return True

    def host_entry_controls_visible(self,s,occurrence):
        # Position both controls BEFORE one-shot typing. No capture, retyping,
        # post-input retry or inference that an absent/disabled Submit is ready.
        def checked(frame):
            C.require(frame['phase']==s['phase'] and frame['owner']==s['owner']
                      and frame['subphase']==s['subphase'] and frame['focused']
                      and frame['host_input'] and not frame['secret_input'],'input_phase')
            self.native.check_host_editor(frame,occurrence)
            C.require(frame['host_observation']['editor']['ordinal']==self.host_lines,'input_phase')
            controls=[self.find(frame,tag,None) for tag in ('HostEditor','HostSubmit')]
            C.require(all(w is None or w['enabled'] for w in controls),'input_disabled')
            outer=self.find(frame,'ScrollRegion',None)
            C.require(outer is not None and outer['enabled'],'input_widget')
            top,bottom=outer['rect'][1],outer['rect'][3]
            # The editor/caret needs interior space; the final Submit can meet
            # the lower edge exactly at egui's content-size scroll clamp.
            for i,w in enumerate(controls):
                if w is None:continue
                a,b,c,d=w['rect'];scale=frame['pixels_per_point']
                x,y=int((a+c)*scale/2)/scale,int((b+d)*scale/2)/scale
                if not (a<x<c and b<y<d and (top<b<d<bottom if i==0 else top<=b<d<=bottom)):
                    controls[i]=None
            return controls
        controls=checked(s)
        if all(w is not None for w in controls):return True
        latest=self.native.stable(s['phase'],s['owner'],protected=True)
        controls=checked(latest)
        if all(w is not None for w in controls):return False # Fresh outer pass before typing.
        tag='HostEditor' if controls[0] is None else 'HostSubmit'
        key=(s['phase'],s['subphase'],'seek',tag,None)
        count=self.scrolls.get(key,0);self.scrolls[key]=count+1
        C.require(count<64,'input_widget')
        editor=self.find(latest,'HostEditor',None)
        if controls[0] is None and self.find(latest,'HostSubmit',None) is not None:direction='up'
        elif editor is not None:
            outer=self.find(latest,'ScrollRegion',None)['rect']
            direction=('down' if editor['rect'][1]>outer[1] else 'up' if editor['rect'][3]<outer[3]
                       else 'up' if count<24 else 'down')
        else:direction='up' if count<24 else 'down'
        self.scroll(latest,'ScrollRegion',None,direction)
        return False

    def pump_host(self,s):
        h=s['host_observation'];context=(h['revision'],h['nonws_end'])
        if self.pending_host is not None:
            # The Begin click's frame is marked protected BEFORE the native
            # tail opens its editor. That real Idle+protected boundary is wait,
            # not permission to type or a fabricated Editing observation.
            occurrence=self.pending_occurrence
            C.require(h['context_valid'] and context==(occurrence[2],occurrence[1]),'input_phase')
            if h['entry']=='Idle':return True
            self.native.check_host_editor(s,occurrence)
            C.require(h['editor']['ordinal']==self.host_lines,'input_phase')
            if not self.host_entry_controls_visible(s,occurrence):return True
            if self.pending_startup is not None:
                C.require(not self.startup_input_attempted,'replay')
                self.startup_input_attempted=True
            kind,value=self.pending_host
            self.host_action='TypingRequested'
            if kind=='secret':self.native.protected_input(s['phase'],s['owner'],'HostEditor',self.fixture.secret('host'),occurrence)
            else:self.native.public_host_line(s['phase'],s['owner'],value,occurrence)
            self.host_action='TypingReturned'
            fresh=self.snapshot()
            self.host_action='SubmitRequested'
            self.press(fresh,'HostSubmit',None,ordinal=self.host_lines)
            self.host_action='SubmitReturned'
            if self.pair_prompt is not None and self.pair_prompt[1]==occurrence:
                target,_,purpose=self.pair_prompt
                if purpose=='Pair':
                    C.require(target==self.current_owner() and self.reviewer_index==int(target[-1])
                              and s['phase']=='Selecting' and s['owner'] is None,'input_phase')
                    self.pair_navigation_submitted[target]=(occurrence,self.host_lines)
                self.pair_prompt=None
            if self.pending_startup is not None:self.startup_submitted()
            self.pending_host=None;self.pending_occurrence=None;return True
        if self.startup_waiting:
            C.require(not s['secret_input'],'input_phase')
            if s['host_input']:
                self.controller.wait_render_progress();return True
            self.startup_waiting=False
            if self.startup_index==len(HOST_STARTUP):
                if self.expected_profile==C.SEMANTIC_PROFILE:
                    C.require(self._startup_ceiling is not None and time.monotonic_ns()<self._startup_ceiling,'deadline')
                    # Actual Idle ends submission waiting, not commands
                    # consumption. Retain the final slot until its native message.
                else:return False
        if self.startup_index<len(HOST_STARTUP):
            C.require(not(s['secret_input'] or s['host_input']),'input_phase')
        if s['host_input']:
            # A submitted later Host line can remain in native Writing after
            # pending_host is consumed. Hold every Source action/outer scroll
            # until genuine idle; no capture, retyping, or deadline renewal.
            C.require(not s['secret_input'],'input_phase')
            self.controller.wait_render_progress();return True
        if s['secret_input']:return False
        if not h['context_valid'] or h['entry']!='Idle':return False
        if (self.expected_profile==C.SEMANTIC_PROFILE and self.startup_index==len(HOST_STARTUP)
                and not self.commands_instruction_observed):
            return self.observe_commands_instruction(s)
        if context==self.commands_instruction_context:return False # Known noninteractive native tail.
        self.host_action='NoPending'
        if self.host_prepared is not None:
            occurrence,line=self.host_prepared
            C.require(context==(occurrence[2],occurrence[1]),'input_phase')
            button=self.find(s,'BeginHostLine',None)
            if button is None:return not self.seek(s,'BeginHostLine',None)
            if not button['enabled']:return False
            self.host_lines+=1;C.input_budget(self.host_lines<=128,'host_lines',self.host_lines)
            self.host_occurrences.latch(occurrence)
            self.pending_host=line;self.pending_occurrence=occurrence;self.host_prepared=None
            if self.startup_index<len(HOST_STARTUP):self.pending_startup=self.startup_index
            self.host_action='BeginRequested'
            self.press(s,'BeginHostLine',None,ordinal=self.host_lines)
            self.host_action='BeginReturned';return True
        # Source review navigation must not be stolen by stale or already
        # inspected nonprompt output. Readiness cannot renew consumed bytes.
        if h['nonws_end']<=self.host_occurrences.frontier:return False
        if self.host_ignored is not None and self.host_ignored[:2]==context:
            # The output can be unchanged while outer scrolling reveals more
            # of its complete prompt. Only equal/narrower coverage stays cached.
            if h['view'] is None or h['view']['nonws']<=self.host_ignored[2]:
                if self.host_coverage_context==context:return self.seek_host_coverage(s)
                return False
        cached=self.host_deferred
        if cached is not None and (cached[0][2],cached[0][1])==context:
            occurrence,suffix=cached
        else:
            self.host_deferred=None
            button=self.find(s,'BeginHostLine',None)
            if button is None:
                # These waiting phases need ordinary Host export/read approval; an unconsumed native Host
                # context may need ordinary navigation before capture. This
                # grants no prompt/approval authority and never resets a budget.
                if s['phase'] in ('V3Receiving','ReturnReading'):return self.seek_waiting_host_control(s,'BeginHostLine')
                return False
            if not button['enabled']:return False
            # Cooldown suppresses repeated inspection of the SAME native output,
            # not a new validated output occurrence. Capture/currentness/grammar
            # and original budgets still decide whether any input is permitted.
            same_capture_context=(self.last_capture is None or self.last_capture[:2]==context)
            if same_capture_context and time.monotonic_ns()-self.last_ocr<self.ocr_delay:return False
            output=self.find(s,'HostOutput',None)
            if output is None:
                if s['phase'] in ('V3Receiving','ReturnReading'):return self.seek_waiting_host_control(s,'HostOutput')
                return False
            if h['view'] is None:
                self.host_rejection='tail_not_visible'
                return self.seek_host_tail(s)
            self.last_ocr=time.monotonic_ns()
            try:text,observed=self.native.capture_host(s['phase'],s['owner'],self.ocr)
            except S.HostObservationChanged:
                # No input was attempted and no text was admitted. Re-enter only
                # through the outer fresh snapshot, never dispatch from stale s.
                return True
            except C.Rejected:
                self.host_rejection='capture_guard'
                self.host_capture_outcome='capture_guard';self.host_capture_context=None
                raise
            self.cache_host_observation(observed)
            self.host_capture_context=(observed['revision'],observed['nonws_end'])
            digest=(observed['revision'],observed['nonws_end'],hashlib.sha256(text.encode()).digest())
            self.ocr_delay=min(8_000_000_000,self.ocr_delay*2) if digest==self.last_capture else 1_000_000_000
            self.last_capture=digest
            try:occurrence,suffix=self.host_occurrences.inspect(text,observed)
            except H.HostContextRejected as error:
                self.host_rejection=error.code;self.host_capture_outcome=error.code
                if error.code in ('host_occurrence_replay','host_capture_grammar'):
                    self.host_ignored=(observed['revision'],observed['nonws_end'],observed['view']['nonws'])
                    if (error.code=='host_capture_grammar' and observed['view']['nonws']<observed['nonws_end']
                            and H.clipped_prompt_tail(text)):
                        new_context=(observed['revision'],observed['nonws_end'])
                        if self.host_coverage_context!=new_context:self.host_coverage_steps=0
                        self.host_coverage_context=new_context
                        return self.seek_host_coverage(s)
                    return False
                error=C.Rejected('snapshot');error.snapshot_reason='HostContext'
                raise error from None
            target=self.initial_pair_navigation_target(s)
            self.pair_prompt=None
            if target is not None and H.APPROVAL.fullmatch(suffix):
                C.require(self.reviewer_index==int(target[-1]),'input_phase')
                purpose=self.initial_pair_purpose(text,observed,occurrence,suffix)
                if purpose is None and observed['view']['nonws']<observed['nonws_end']-self.host_occurrences.frontier:
                    # Unknown generic purposes retain the original approval path
                    # only when this validated suffix covers ALL fresh non-whitespace bytes.
                    # A clipped Pair cannot be submitted without classification.
                    self.host_capture_outcome='host_capture_grammar';self.host_rejection='host_capture_grammar'
                    self.host_ignored=(observed['revision'],observed['nonws_end'],observed['view']['nonws'])
                    captured_context=(observed['revision'],observed['nonws_end'])
                    if self.host_coverage_context!=captured_context:self.host_coverage_steps=0
                    self.host_coverage_context=captured_context
                    return self.seek_host_coverage(s)
                if purpose is not None:self.pair_prompt=(target,occurrence,purpose)
            self.host_capture_outcome='Accepted';self.host_rejection=None
            self.host_coverage_context=None
            self.host_deferred=(occurrence,suffix)
        self.host_stage=H.stage(suffix)
        line=self.expected_host_line(suffix)
        if line is None:return False
        if self.pair_prompt is not None and self.pair_prompt[1]==occurrence:
            C.require(line==('public',H.APPROVAL.fullmatch(suffix).group(1)),'input_phase')
        self.host_prepared=(occurrence,line);self.host_deferred=None
        # Capture may admit a newer context than s. Never dispatch prepared
        # input against that stale pre-capture snapshot; re-observe normally.
        if context!=(occurrence[2],occurrence[1]):return True
        return self.pump_host(s)
    def cache_input_checkpoint(self,s,target):
        # Only already-validated main-loop observations. No raw values or geometry.
        rows=[[5 if self.used(s,tag,role) else 0 for tag in C.INPUT_WIDGET_TAGS]
              for role in (None,'Signer1','Signer2')]
        for w in s['widgets']:
            row=(None,'Signer1','Signer2').index(w['owner'])
            rows[row][C.INPUT_WIDGET_TAGS.index(w['tag'])]=1+int(w['enabled'])+2*int(self.used(s,w['tag'],w['owner']))
        self.input_checkpoint=dict(phase=s['phase'],subphase=s['subphase'],owner=s['owner'],target=target,widget_states=rows)

    def run(self):
        while True:
            s=self.snapshot();phase=s['phase'];owner=s['owner'];target=self.current_owner()
            if self.password_pending is not None:self.password_guard(s,s)
            self.cache_input_checkpoint(s,target)
            # Failure LOCATION is the last validated main-loop nonterminal checkpoint,
            # not the current terminal state or an attribution of its cause.
            if phase not in ('Revoked','Finished'):
                self.location={'phase':phase,'subphase':s['subphase'],'owner':owner}
            phase_key=(phase,s['subphase'],owner)
            if phase_key!=self.last_phase:
                self.scrolls={};self.search_geometry=None;self.search_direction='up';self.last_phase=phase_key
            if phase=='Revoked' and self.pending_host is not None:
                # Boundary diagnostic only: Begin was latched, but typing and
                # guarded Submit have not both returned. No cause/acceptance claim.
                # The pump has no outer-loop yield between typing and Submit.
                self.host_rejection='host_entry_changed'
            C.require(phase not in ('Revoked',),'source_failure')
            if phase=='Finished':
                self.native.close_after_normal_proof(self.records,owner,self.expected_profile);return
            if not s['focused']:
                # Observe initial compositor focus only; never refocus or renew
                # the original deadline, and reject any later focus loss.
                C.require(not self.startup_focus_seen and phase=='Selecting' and owner is None and
                          s['subphase']=='None' and not(s['secret_input'] or s['host_input']),'input_phase')
                self.startup_focus_waits+=1;C.input_budget(self.startup_focus_waits<64,'startup_focus',self.startup_focus_waits)
                self.controller.wait_render_progress();continue
            self.startup_focus_seen=True
            if not self.host_startup_complete:
                C.require(phase=='Selecting' and owner is None and s['subphase']=='None','input_phase')
            if phase in ('V3Password','Password'):
                self.password_step(s)
                continue
            if s['secret_input']:
                # CI conservatively marks the entry-intent frame protected
                # before its native tail changes V3Confirm/EntryConfirm phase.
                # Observe only our exact already-consumed entry action; this
                # latch grants no input, approval, or native completion evidence.
                entering={'V3Confirm':'PasswordV3','EntryConfirm':'EnterPassword'}.get(phase)
                C.require(not s['host_input'] and owner in ('Signer1','Signer2') and
                          entering is not None and self.used(s,entering,owner),'input_phase')
                self.controller.wait_render_progress();continue
            if self.operator is not None:
                for role in ('Signer1','Signer2'):
                    audited=next((r for r in self.records if r['kind']=='SignerMilestone' and r['facts']=={'owner':role,'step':'AdmissionAudited'}),None)
                    if audited:self.operator.signal(role,'audit_stop',audited)
                retired=next((r for r in self.records if r['kind']=='SignerMilestone' and r['facts']=={'owner':'Signer1','step':'SigningRetired'}),None)
                if retired:self.operator.signal('Signer2','start',retired)
            if self.selection_handoff_pending(s):continue
            if self.pump_host(s):continue
            if not self.host_startup_complete:
                # Native startup is independent of Signer selection. Do not
                # mistake unchanged Selecting for permission to skip its prompts.
                if self.find(s,'BeginHostLine',None) is None or self.find(s,'HostOutput',None) is None:
                    self.seek(s,'HostOutput' if self.find(s,'HostOutput',None) is None else 'BeginHostLine',None)
                else:self.controller.wait_render_progress()
                continue
            if phase in ('SetupNeeded','Selecting','SignCommitted','SignedRetired','ReturnCompleted'):
                saved=False
                for role in ('Signer1','Signer2'):
                    if self.save_selector(s,role,'continue') or self.save_selector(s,role,'result'):
                        saved=True;break
                if saved:continue
            if phase in FORMS:
                kind,action=FORMS[phase];complete=True
                for field,value in self.fixture.form(owner,kind).items():
                    if not self.field(s,'Field:'+field,owner,value):complete=False;break
                if complete and not self.used(s,action,owner):
                    # Multiline public forms can push their submit below the
                    # viewport. Use bounded ordinary navigation, never retype a
                    # consumed field or infer that an unseen action is enabled.
                    if self.seek(s,action,owner) and self.find(s,action,owner)['enabled']:
                        self.press(s,action,owner)
                continue
            if phase in REVIEW:self.review(s,REVIEW[phase],owner);continue
            if phase in READ_ONLY:self.review(s,READ_ONLY[phase],owner,ack=None);continue
            if phase in CONFIRM:self.review(s,CONFIRM[phase],owner);continue
            if phase=='AdmissionReview':
                self.paired_admission(s,owner)
                continue
            if phase=='WriterFlow' and s['subphase'] in ('SetupNeeded','SetupReview','ServiceReview','ReadReview','AcquireReview'):
                self.review(s,'WriterAction',owner,ack=None if s['subphase']=='SetupNeeded' else 'ReviewAcknowledgement');continue
            if phase=='CompletedPairFlow' and s['subphase'] in ('SetupReview','ServeReview'):
                self.review(s,'CompletedPairAction',owner);continue
            if phase=='SignCommitted':
                # H must be able to select the actual saved result before W retires.
                path=self.fixture.source_path(owner,'result_output_file')
                if self.result_index<int(owner[-1]) or self.pending_host is not None:
                    self.idle_scan(s);continue
                if pathlib.Path(path).exists() and not self.used(s,'RetireSigning',owner):
                    if self.seek(s,'RetireSigning',owner):self.press(s,'RetireSigning',owner)
                continue
            if phase in DIRECT:
                if phase=='SetupNeeded' and (self.continue_index<int(owner[-1]) or self.pending_host is not None):
                    self.idle_scan(s);continue
                action=DIRECT[phase]
                if not self.used(s,action,owner) and self.seek(s,action,owner):
                    if self.find(s,action,owner)['enabled']:self.press(s,action,owner)
                continue
            if phase=='FinancialSetupSelected':
                if (not self.used(s,'Configure',owner) and self.financial_selection_ready(owner)
                        and self.seek(s,'Configure',owner)):self.press(s,'Configure',owner)
                continue
            if phase=='Selecting' or phase in RESULT_PHASES:
                if self.milestone('Signer1','SigningRetired') and self.milestone('Signer2','SigningRetired'):
                    if not self.host_milestone('CompletedPairRetained'):
                        w=self.find(s,'PrepareCompletedPair',None)
                        if w and w['enabled'] and not self.used(s,'PrepareCompletedPair',None):self.press(s,'PrepareCompletedPair',None);continue
                    elif target is not None:
                        w=self.find(s,'ResumeFinancial',target)
                        if w and w['enabled'] and not self.used(s,'ResumeFinancial',target):self.press(s,'ResumeFinancial',target);continue
                else:
                    selected=False
                    for action in SELECT:
                        w=self.find(s,action,target)
                        if w and w['enabled'] and not self.used(s,action,target):
                            if action in ('ConfigureFinancialSetup','Configure') and not self.financial_selection_ready(target):continue
                            self.press(s,action,target);self.pending_selection=phase_key;selected=True;break
                    if selected:continue
                if phase in RESULT_PHASES and self.find(s,'SelectNextV3',owner) and not self.used(s,'SelectNextV3',owner):
                    self.press(s,'SelectNextV3',owner);self.pending_selection=phase_key;continue
                if self.reserve_initial_pair_navigation(s,target):continue
                if self.waiting_for_host_admission(s,target):continue
                if not self.wait_initial_pair_after_sweep(s,target):self.idle_scan(s)
            elif phase=='Waiting':self.idle_scan(s)
            # All other phases wait actual observations under original deadline.
            # No phase change, request, outcome or authority is fabricated here.
