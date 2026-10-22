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
SELECT=('ReviewV3Pair','ReviewV3Enrollment','ReviewV3Manifest','ReviewV3RedisclosureRead',
        'ReviewV3Redisclose','ConfigureV3Owner','ReviewV3PrepareRead','ReviewV3Receive',
        'ReviewV3AdmitRead','ReviewV3Admit','ReviewV3Audit','ConfigureFinancialSetup','Configure','ConfigureV3')
RESULT_PHASES=frozenset(('V3Held','V3Paired','V3Enrolled','V3ManifestAccepted','V3RedisclosurePrepared',
 'V3Redisclosed','V3OwnerSelected','V3Prepared','V3Received','V3AdmitReadRetained','V3AdmissionRetained','V3Audited'))

class FullFlow:
    def __init__(self,controller,fixture,observer,ocr,operator=None):
        self.operator=operator
        self.expected_profile=observer.expected_profile
        self.controller=controller;self.fixture=fixture;self.observer=observer;self.ocr=ocr
        self.native=S.NativeScenario(controller,fixture,observer.next_snapshot)
        self.done=set();self.filled=set();self.scrolls={};self.actions=0;self.host_lines=0
        self.last_ocr=0;self.ocr_delay=1_000_000_000;self.last_capture=None;self.last_rendered=None;self.challenges=set();self.host_paths=set()
        self.reviewer_index=0;self.continue_index=0;self.result_index=0
        self.records=[];self.pending_host=None;self.location=None
        self.last_phase=None;self.search_direction='up';self.search_geometry=None
    def snapshot(self):
        self.fixture.check();snapshot=self.native.snapshot()
        # next_snapshot may observe later records while awaiting a fresh frame.
        # Refresh AFTER that read: Finished is not normal-completion proof, and
        # the exact native proof guard must not receive a pre-frame record set.
        # ObserverFiles retains append-only validation and the original deadline.
        self.records=self.observer.read()
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
    def current_owner(self):
        for owner in ('Signer1','Signer2'):
            if not self.milestone(owner,'SigningRetired'):return owner
        for owner in ('Signer1','Signer2'):
            if not self.milestone(owner,'ReturnFinished'):return owner
        return None
    def press(self,s,tag,owner,*,ordinal=None):
        key=self.key(s,tag,owner)+(ordinal,)
        C.require(key not in self.done,'replay')
        # Two real later frames before one effect. Repeated observations may wait;
        # an attempted effect is latched BEFORE send and never retried.
        latest=self.native.stable(s['phase'],s['owner'],protected=s['secret_input'] or s['host_input'])
        C.require(latest['subphase']==s['subphase'],'input_phase')
        w=self.find(latest,tag,owner);C.require(w is not None and w['enabled'],'input_disabled')
        self.done.add(key);self.actions+=1;C.require(self.actions<=512,'input_budget')
        self.controller.click(*self.native.point(latest,tag,owner));self.controller.wait_render_progress()
    def used(self,s,tag,owner):return self.key(s,tag,owner)+(None,) in self.done
    def scroll(self,s,body,owner,direction='down'):
        w=self.find(s,body,owner)
        if w is None:return False
        key=(s['phase'],s['subphase'],body,owner,direction)
        count=self.scrolls.get(key,0);C.require(count<128,'input_budget');self.scrolls[key]=count+1
        action=self.controller.scroll_up if direction=='up' else self.controller.scroll_down
        point=self.native.point(s,body,owner)
        if body=='ScrollRegion':
            x0,y0,x1,y1=w['rect'];scale=s['pixels_per_point']
            inners=[a['rect'] for a in s['widgets'] if a['tag'] in ('ReviewBody','SignerReviewBody','WitnessReviewBody','HostOutput')]
            points=[(x1-3,y0+5+(y1-y0-10)*i/8) for i in range(9)]
            clear=next(((x,y) for x,y in points if not any(a<=x<=c and b<=y<=d for a,b,c,d in inners)),None)
            C.require(clear is not None,'input_widget');point=tuple(int(v*scale) for v in clear)
        action(*point);self.controller.wait_render_progress();return True
    def seek(self,s,tag,owner):
        if self.find(s,tag,owner) is not None:return True
        # Ordinary native wheel search only; no click on an invented rectangle.
        key=(s['phase'],s['subphase'],'seek',tag,owner)
        count=self.scrolls.get(key,0);self.scrolls[key]=count+1
        C.require(count<64,'input_widget')
        self.scroll(s,'ScrollRegion',None,'up' if count<24 else 'down');return False
    def idle_scan(self,s):
        # Search the actual panel in both directions. A stable observed boundary
        # reverses native wheel direction; no scroll position is read or set.
        geometry=tuple((w['tag'],w['owner'],tuple(w['rect']),w['enabled']) for w in s['widgets'])
        if geometry==self.search_geometry:self.search_direction='down' if self.search_direction=='up' else 'up'
        self.search_geometry=geometry
        return self.scroll(s,'ScrollRegion',None,self.search_direction)
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
        if self.used(s,action,owner):return False
        checkbox=self.find(s,ack,owner) if ack else None
        if ack and not self.used(s,ack,owner):
            if checkbox is not None and checkbox['enabled']:
                self.press(s,ack,owner);return True
            if self.seek(s,ack,owner):return False
            return True
        button=self.find(s,action,owner)
        if button is not None and button['enabled']:
            self.press(s,action,owner);return True
        # A checkbox is not evidence of reading; actual C keeps action disabled
        # until the complete native scroll review end has genuinely painted.
        if button is None:return not self.seek(s,action,owner)
        if self.scroll(s,body,owner):return True
        return not self.seek(s,body,owner)
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
    def expected_host_line(self,rendered):
        # OCR whitespace wrapping may vary; characters/challenge are never repaired.
        text=' '.join(rendered.split())
        digest=hashlib.sha256(text.encode()).digest()
        if digest==self.last_rendered:return None
        self.last_rendered=digest
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
                self.last_rendered=None;return None
            owner='Signer'+str(self.reviewer_index+1);source=self.fixture.source(owner)
            scope=source['original_capture']['scope']
            participant=scope['participant_id']
            C.require(type(participant) is str and participant,'fixture')
            self.reviewer_index+=1
            # New inert operation names only; account/participant/choices come
            # from actual preserved fixture, not a grant or speculative result.
            value={'import_operation_id':f'full-native-import-{self.reviewer_index}',
                   'redisclosure_operation_id':f'full-native-redisclose-{self.reviewer_index}',
                   'account_id':source['entry_selection']['account_id'],
                   'participant_id':participant,'choices':self.fixture._data['delivery_choices']}
            return ('public',json.dumps(value,separators=(',',':')))
        for prompt,kind,counter in (
          ('Exact copied native continuation selector JSON file','continuation_output_file','continue_index'),
          ('Exact copied native AwaitingReturn result selector JSON file','result_output_file','result_index')):
            if prompt in text:
                index=getattr(self,counter)
                if index>=2:return None
                if index==1 and not self.host_milestone('Owner1SigningRetired'):
                    self.last_rendered=None;return None
                owner='Signer'+str(index+1);path=self.fixture.source_path(owner,kind)
                if not pathlib.Path(path).exists():self.last_rendered=None;return None
                self.fixture.source_path(owner,kind,must_exist=True);setattr(self,counter,index+1)
                return ('public',path)
        matches=re.findall(r'Type (APPROVE [0-9a-f]{16}) to approve this exact operation,',text)
        if matches:
            challenge=matches[-1]
            if challenge in self.challenges:return None
            C.require(len(self.challenges)<96,'input_budget');self.challenges.add(challenge)
            return ('public',challenge)
        return None
    def pump_host(self,s):
        if self.pending_host is not None:
            if not s['host_input']:return True
            kind,value=self.pending_host
            if kind=='secret':self.native.protected_input(s['phase'],s['owner'],'HostEditor',self.fixture.secret('host'))
            else:self.native.public_host_line(s['phase'],s['owner'],value)
            fresh=self.snapshot()
            self.press(fresh,'HostSubmit',None,ordinal=self.host_lines)
            self.pending_host=None;return True
        if s['secret_input'] or s['host_input']:return False
        button=self.find(s,'BeginHostLine',None)
        if button is None or not button['enabled']:return False
        if time.monotonic_ns()-self.last_ocr<self.ocr_delay:return False
        output=self.find(s,'HostOutput',None)
        if output is None:return False
        self.last_ocr=time.monotonic_ns()
        text=self.native.capture_host(s['phase'],s['owner'],self.ocr)
        digest=hashlib.sha256(text.encode()).digest()
        self.ocr_delay=min(8_000_000_000,self.ocr_delay*2) if digest==self.last_capture else 1_000_000_000
        self.last_capture=digest
        line=self.expected_host_line(text)
        if line is None:return False
        self.host_lines+=1;C.require(self.host_lines<=128,'input_budget')
        self.pending_host=line;self.press(s,'BeginHostLine',None,ordinal=self.host_lines);return True
    def host_startup_probe(self):
        """PRIVATE failure-only OCR discriminator; never selects a Source/reviewer.

        Only four initial Host lines may be submitted, in native prompt order.
        Seeing the next reviewer prompt after those submissions deliberately
        fails missing_evidence, not normal completion or a native milestone.
        Initial focus may lag startup; once seen, focus loss remains fatal.
        Startup focus/search is capped at64 observations, OCR at64 captures.
        Asynchronous Writing/reply waits use real render progress, bounded by
        the unchanged controller progress budget and original fixture deadline.
        """
        markers=('Existing original Host profile directory (absolute):',
                 'Existing original dispatcher workspace directory (absolute):',
                 'Storage passphrase:', 'Exact immutable command keys JSON file',
                 'Exact coordinated reviewer selection JSON',
                 'Exact copied native continuation selector JSON file',
                 'Exact copied native AwaitingReturn result selector JSON file',
                 'Type APPROVE ')
        submitted=0;pending=None;awaiting_clear=False;focus_seen=False;search_attempts=0
        startup_observations=0;captures=0
        def check(s):
            C.require(s['phase']=='Selecting' and s['owner'] is None and
                      s['subphase']=='None' and not s['secret_input'],'input_phase')
        while True:
            C.require(startup_observations<64,'input_budget')
            s=self.snapshot()
            if s['phase'] not in ('Revoked','Finished'):
                self.location={k:s[k] for k in ('phase','subphase','owner')}
            check(s)
            if not s['focused']:
                C.require(not focus_seen and not s['host_input'] and pending is None and
                          not awaiting_clear,'input_phase')
                startup_observations+=1
                self.controller.wait_render_progress();continue
            focus_seen=True
            if pending is not None:
                if not s['host_input']:
                    self.controller.wait_render_progress();continue
                kind,value=pending
                if kind=='secret':
                    self.native.protected_input('Selecting',None,'HostEditor',self.fixture.secret('host'))
                else:self.native.public_host_line('Selecting',None,value)
                fresh=self.snapshot();check(fresh)
                C.require(fresh['focused'] and fresh['host_input'],'input_phase')
                self.press(fresh,'HostSubmit',None,ordinal=self.host_lines)
                submitted+=1;pending=None;awaiting_clear=True
                continue
            if s['host_input']:
                # Only the just-submitted, still-draining owned slot may remain.
                C.require(awaiting_clear,'input_phase')
                self.controller.wait_render_progress();continue
            awaiting_clear=False
            button=self.find(s,'BeginHostLine',None)
            if button is None or not button['enabled'] or self.find(s,'HostOutput',None) is None:
                startup_observations+=1
                C.require(self.scroll(s,'ScrollRegion',None,'up' if search_attempts<8 else 'down'),'input_widget')
                search_attempts+=1;continue
            now=time.monotonic_ns()
            if now-self.last_ocr<self.ocr_delay:
                self.controller.wait_render_progress();continue
            C.require(captures<64,'input_budget');captures+=1;self.last_ocr=now
            text=' '.join(self.native.capture_host('Selecting',None,self.ocr).split())
            digest=hashlib.sha256(text.encode()).digest()
            self.ocr_delay=min(8_000_000_000,self.ocr_delay*2) if digest==self.last_capture else 1_000_000_000
            self.last_capture=digest
            positions=[(text.rfind(marker),index) for index,marker in enumerate(markers) if marker in text]
            if not positions:
                self.controller.wait_render_progress();continue
            current=max(positions)[1]
            C.require(current<=submitted,'input_phase')
            if current<submitted:
                # Old/wrapped/repeated output cannot consume a line twice or stop.
                self.controller.wait_render_progress();continue
            if current==4:
                raise C.Rejected('missing_evidence')
            C.require(submitted<4,'input_phase')
            if current==2:pending=('secret',None)
            else:
                key=('profile','workspace',None,'session_commands_file')[current]
                pending=('public',self.fixture.top_path(key))
            self.host_lines+=1
            self.press(s,'BeginHostLine',None,ordinal=self.host_lines)

    def run(self):
        while True:
            s=self.snapshot();phase=s['phase'];owner=s['owner'];target=self.current_owner()
            # Failure LOCATION is the last validated main-loop nonterminal checkpoint,
            # not the current terminal state or an attribution of its cause.
            if phase not in ('Revoked','Finished'):
                self.location={'phase':phase,'subphase':s['subphase'],'owner':owner}
            phase_key=(phase,s['subphase'],owner)
            if phase_key!=self.last_phase:
                self.scrolls={};self.search_geometry=None;self.search_direction='up';self.last_phase=phase_key
            C.require(phase not in ('Revoked',),'source_failure')
            if phase=='Finished':
                self.native.close_after_normal_proof(self.records,owner,self.expected_profile);return
            if phase in ('V3Password','Password'):
                if not self.used(s,'PasswordSubmit',owner):
                    self.native.protected_input(phase,owner,'SourcePassword',self.fixture.secret('source'))
                    fresh=self.snapshot();self.press(fresh,'PasswordSubmit',owner)
                continue
            if self.operator is not None:
                for role in ('Signer1','Signer2'):
                    audited=next((r for r in self.records if r['kind']=='SignerMilestone' and r['facts']=={'owner':role,'step':'AdmissionAudited'}),None)
                    if audited:self.operator.signal(role,'audit_stop',audited)
                retired=next((r for r in self.records if r['kind']=='SignerMilestone' and r['facts']=={'owner':'Signer1','step':'SigningRetired'}),None)
                if retired:self.operator.signal('Signer2','start',retired)
            if self.pump_host(s):continue
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
                if complete and self.find(s,action,owner) and self.find(s,action,owner)['enabled'] and not self.used(s,action,owner):self.press(s,action,owner)
                continue
            if phase in REVIEW:self.review(s,REVIEW[phase],owner);continue
            if phase in READ_ONLY:self.review(s,READ_ONLY[phase],owner,ack=None);continue
            if phase in CONFIRM:self.review(s,CONFIRM[phase],owner);continue
            if phase=='AdmissionReview':
                if not self.used(s,'ArmSigner',owner):self.review(s,'ArmSigner',owner,ack='SignerReviewAcknowledgement',body='SignerReviewBody')
                elif not self.used(s,'ArmWitness',owner):self.review(s,'ArmWitness',owner,ack='WitnessReviewAcknowledgement',body='WitnessReviewBody')
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
                if self.seek(s,'Configure',owner) and not self.used(s,'Configure',owner):self.press(s,'Configure',owner)
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
                            if self.operator is not None and action in ('ConfigureFinancialSetup','Configure'):
                                if not self.operator.parked(target):continue
                                self.operator.financial_gate(target,self.records)
                            self.press(s,action,target);selected=True;break
                    if selected:continue
                if phase in RESULT_PHASES and self.find(s,'SelectNextV3',owner) and not self.used(s,'SelectNextV3',owner):
                    self.press(s,'SelectNextV3',owner);continue
                self.idle_scan(s)
            elif phase=='Waiting':self.idle_scan(s)
            # All other phases wait actual observations under original deadline.
            # No phase change, request, outcome or authority is fabricated here.
