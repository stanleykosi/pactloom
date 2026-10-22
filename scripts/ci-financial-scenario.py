#!/usr/bin/env python3
"""Guarded native action primitives for the full financial qualification.

This is not an alternative authority API. A runner supplies the actual bounded
observer reader and compositor controller; all effects use native input. There
is deliberately no 'success' fallback when those integrations are unavailable.
"""
import hashlib
import importlib.util
import pathlib
import os
import selectors
import re
import subprocess
import sys
import time

ROOT=pathlib.Path(__file__).parent

def module(name):
    key=name.replace('-','_');spec=importlib.util.spec_from_file_location(key,ROOT/(name+'.py'))
    result=importlib.util.module_from_spec(spec);sys.modules[key]=result;spec.loader.exec_module(result)
    return result
C=module('ci-financial-contract')
F=module('ci-financial-fixture')
K=module('ci-financial-controller')

class HostObservationChanged(Exception):
    """A read-only semantic Host bracket crossed a genuine source transition."""

class NativeScenario:
    """One actual fixture and target; no retries, rebinding or renewed clocks."""
    def __init__(self,controller,fixture,next_snapshot,*,expected_profile=C.PROFILE,host_view=None,wait_ceiling=None):
        C.require(expected_profile in (C.PROFILE,C.EXTERNAL_PROFILE,C.SEMANTIC_PROFILE))
        C.require((host_view is not None)==(expected_profile==C.SEMANTIC_PROFILE))
        C.require(wait_ceiling is None or (expected_profile==C.SEMANTIC_PROFILE and callable(wait_ceiling)))
        self.expected_profile=expected_profile;self.host_view=host_view;self.wait_ceiling=wait_ceiling
        self.controller=controller;self.fixture=fixture;self.next_snapshot=next_snapshot
        self._used=set();self._protected=False;self._generation=0
        fixture.preflight_input_budget()
    def snapshot(self):
        self.fixture.check();deadline=self.fixture.deadline_ns
        if self.wait_ceiling is not None:
            bound=self.wait_ceiling()
            C.require(bound is None or (type(bound) is int and bound>0),'deadline')
            if bound is not None:deadline=min(deadline,bound)
            C.require(time.monotonic_ns()<deadline,'deadline')
        s=C.validate_snapshot(self.next_snapshot(deadline),self.expected_profile)
        if self.wait_ceiling is not None:C.require(time.monotonic_ns()<deadline,'deadline')
        C.require(s['view_generation']>self._generation,'replay')
        self._generation=s['view_generation'];return s
    def stable(self,phase,owner,*,protected=False):
        """Two later actual UI frames separated by genuine render progress."""
        first=self.snapshot();self.controller.wait_render_progress();second=self.snapshot()
        for s in (first,second):
            C.require(s['phase']==phase and s['owner']==owner and s['focused'],'input_phase')
            C.require(protected or not(s['secret_input'] or s['host_input']),'sensitive_capture')
        shape=lambda s:{k:v for k,v in s.items() if k not in ('view_generation','host_observation','host_view_id')}
        C.require(shape(first)==shape(second),'snapshot');return second
    @staticmethod
    def widget(snapshot,tag,owner):
        found=[w for w in snapshot['widgets'] if w['tag']==tag and w['owner']==owner]
        C.require(len(found)==1,'input_widget');w=found[0]
        C.require(w['enabled'],'input_disabled');return w
    def point(self,s,tag,owner):
        x0,y0,x1,y1=self.widget(s,tag,owner)['rect'];scale=s['pixels_per_point']
        return int((x0+x1)*scale/2),int((y0+y1)*scale/2)
    def click(self,phase,owner,tag,*,ordinal=0,protected=False):
        C.require(tag in C.ACTIONS,'input_widget')
        key=(phase,owner,tag,ordinal);C.require(key not in self._used,'replay')
        s=self.stable(phase,owner,protected=protected);point=self.point(s,tag,owner)
        self._used.add(key) # latch before a fallible native effect; never retry.
        self.controller.click(*point);self.controller.wait_render_progress()
    def close_after_normal_proof(self,records,owner,expected_profile=C.PROFILE):
        # Finished alone also covers cancellation. Require actual normal proof
        # observations before the sole final native Close; full oracle follows
        # actual root wait0 and cannot be replaced by these preconditions.
        for record in records:
            C.validate_record(record,expected_profile)
            C.require(record['kind']!='NativeFailureBoundary','observer_failure')
        for kind in ('NormalFinishAdmitted','PtyHeld','PtyReleased','NormalFinished'):
            C.require(sum(r['role']=='Coordinator' and r['kind']==kind for r in records)==1,'normal_finish')
        key=('Finished',None,'Close',0);C.require(key not in self._used,'replay')
        s=self.stable('Finished',owner);point=self.point(s,'Close',None)
        self._used.add(key);self.controller.terminal_click(*point)
        # No further capture/input/progress barrier after terminal native click.
    def form(self,phase,owner,kind):
        for field,value in self.fixture.form(owner,kind).items():
            self.public_field(phase,owner,'Field:'+field,value)
    def public_field(self,phase,owner,tag,value):
        C.require(tag in C.WIDGETS and tag.startswith('Field:'),'input_widget')
        K._ascii_events(value) # reject entire public value before any input.
        key=(phase,owner,tag);C.require(key not in self._used,'replay')
        s=self.stable(phase,owner);point=self.point(s,tag,owner);self._used.add(key)
        self.controller.click(*point);self.controller.clear_field();self.controller.type_ascii(value)
    def review(self,phase,owner,ack='ReviewAcknowledgement',*,max_scrolls=16):
        """Actual scroll to a native-enabled acknowledgement; no read setter."""
        C.require(ack in ('ReviewAcknowledgement','WitnessReviewAcknowledgement','SignerReviewAcknowledgement'),'input_widget')
        C.require(type(max_scrolls) is int and 0<max_scrolls<=16,'input_budget')
        for _ in range(max_scrolls):
            s=self.stable(phase,owner)
            found=[w for w in s['widgets'] if w['tag']==ack and w['owner']==owner]
            if len(found)==1 and found[0]['enabled']:
                self.click(phase,owner,ack);return
            body={'SignerReviewAcknowledgement':'SignerReviewBody','WitnessReviewAcknowledgement':'WitnessReviewBody'}.get(ack,'ReviewBody')
            self.controller.scroll_down(*self.point(s,body,owner))
            self.controller.wait_render_progress()
        raise C.Rejected('input_disabled')
    def protected_input(self,phase,owner,tag,secret,host_context=None):
        """Closed disposable fixture passwords only, never capture during input."""
        C.require(type(secret) is F.SyntheticSecret and tag in ('HostEditor','SourcePassword'),'fixture_secret')
        s=self.stable(phase,owner,protected=True)
        C.require(s['host_input'] if tag=='HostEditor' else s['secret_input'],'input_phase')
        if tag=='HostEditor':self.check_host_editor(s,host_context)
        point=self.point(s,tag,None if tag=='HostEditor' else owner);self._protected=True
        try:
            def native(value):
                # Convert only fixed synthetic bytes, preflight then emit evdev.
                # Do not call public type_ascii or include values in exceptions.
                text=bytes(value).decode('ascii')
                batches=self.controller._preflight_ascii_batches(text,extra_commands=3)
                self.controller.click(*point)
                for events in batches:
                    for key,pressed in events:self.controller._command(K.KEY,key,pressed)
                    self.controller.wait_render_progress()
            secret.consume(native)
        finally:secret.wipe()
        # Remains protected until actual submit and later observer says both
        # protected editors are absent. Never clear merely on successful typing.
    def public_host_line(self,phase,owner,value,host_context=None):
        C.require(type(value) is str and '\n' not in value and '\r' not in value,'input_phase')
        K._ascii_events(value)
        s=self.stable(phase,owner,protected=True);C.require(s['host_input'],'input_phase')
        self.check_host_editor(s,host_context)
        self._protected=True;self.controller.click(*self.point(s,'HostEditor',None))
        self.controller.type_ascii(value)
    @staticmethod
    def check_host_editor(s,occurrence):
        h=s['host_observation'];e=h['editor']
        C.require(occurrence is not None and h['context_valid'] and h['entry']=='Editing'
                  and e is not None and e['revision']==h['revision']==occurrence[2]
                  and h['nonws_end']==occurrence[1] and h['view'] is None,'input_phase')
    @staticmethod
    def _host_read_frames(frames,phase,owner):
        # Validate every consumed frame before considering a harmless transition.
        # Focus loss, protected input and terminal states never become deferrals.
        for s in frames:
            C.require(s['focused'] and s['phase'] not in ('Revoked','Finished'),'input_phase')
            C.require(not(s['secret_input'] or s['host_input']),'sensitive_capture')
        if any(s['phase']!=phase or s['owner']!=owner for s in frames):
            raise HostObservationChanged()
    def host_stable(self,phase,owner):
        # Generic source actions keep legacy semantics; Host capture requires its
        # own stronger exact output/layout equality across genuine later frames.
        semantic=self.expected_profile==C.SEMANTIC_PROFILE
        if semantic:
            # Passive capture may race a source action's genuine pre-tail frame.
            # Effectful stable()/click()/typing retain their exact strict guards.
            a=self.snapshot();self.controller.wait_render_progress();first=self.snapshot()
            self._host_read_frames((a,first),phase,owner)
            source_shape=lambda s:{k:v for k,v in s.items() if k not in ('view_generation','host_observation','host_view_id')}
            C.require(source_shape(a)==source_shape(first),'snapshot')
        else:first=self.stable(phase,owner)
        self.controller.wait_render_progress();second=self.snapshot()
        if semantic:self._host_read_frames((first,second),phase,owner)
        shape=lambda s:{k:v for k,v in s.items() if k!='view_generation'}
        C.require(shape(first)==shape(second),'snapshot')
        h=second['host_observation']
        C.require(h['context_valid'] and h['entry']=='Idle' and h['view'] is not None,'snapshot')
        return second
    def capture_host(self,phase,owner,ocr):
        s=self.host_stable(phase,owner)
        C.require(not s['secret_input'] and not s['host_input'],'sensitive_capture')
        self._protected=False
        if self.expected_profile==C.SEMANTIC_PROFILE:
            text=self.host_view(s)
        else:
            rect=s['host_observation']['view']['rect'];scale=s['pixels_per_point']
            physical=tuple(round(v*scale) for v in rect)
            with self.controller.observe() as frame:
                text=ocr.read(frame,physical,self.fixture.deadline_ns)
        after=self.host_stable(phase,owner)
        C.require({k:v for k,v in s.items() if k!='view_generation'}==
                  {k:v for k,v in after.items() if k!='view_generation'},'snapshot')
        return text,after['host_observation']

def bounded_ocr_process(argv,ppm,deadline_ns):
    """Bound both directions in memory; kill/reap only our own OCR on failure."""
    process=None;output=bytearray();offset=0
    try:
        process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,close_fds=True,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','OMP_THREAD_LIMIT':'1'})
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdin,process.stdout):os.set_blocking(stream.fileno(),False)
            selector.register(process.stdin,selectors.EVENT_WRITE)
            selector.register(process.stdout,selectors.EVENT_READ)
            while selector.get_map():
                remaining=(deadline_ns-time.monotonic_ns())/1e9
                C.require(remaining>0,'deadline')
                ready=selector.select(remaining);C.require(ready,'deadline')
                for key,_ in ready:
                    if key.fileobj is process.stdin:
                        count=os.write(process.stdin.fileno(),memoryview(ppm)[offset:offset+65536]);offset+=count
                        if offset==len(ppm):selector.unregister(process.stdin);process.stdin.close()
                    else:
                        block=os.read(process.stdout.fileno(),min(65536,32769-len(output)))
                        if not block:selector.unregister(process.stdout);process.stdout.close()
                        else:output.extend(block);C.require(len(output)<=32768,'ocr')
        remaining=(deadline_ns-time.monotonic_ns())/1e9;C.require(remaining>0,'deadline')
        C.require(process.wait(timeout=remaining)==0,'ocr')
        return output.decode('ascii','strict')
    except (OSError,UnicodeError,subprocess.SubprocessError):raise C.Rejected('ocr') from None
    finally:
        for i in range(len(output)):output[i]=0
        if process is not None:
            if process.poll() is None:process.kill();process.wait()
            for stream in (process.stdin,process.stdout):
                if stream is not None:stream.close()

class PinnedLocalOcr:
    """Pinned binary, stdin PPM/stdout OCR only; never persists an image.

    The digest MUST come from the independently authenticated Debian 5.5.0
    image lock. No default digest, download, PATH lookup or external OCR API.
    """
    def __init__(self,binary,expected_sha256):
        path=F.absolute(binary)
        C.require(re.fullmatch('[0-9a-f]{64}',expected_sha256 or '') is not None,'ocr_pin')
        try:
            C.require(path.is_file() and not path.is_symlink(),'ocr_pin')
            with path.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
            C.require(actual==expected_sha256,'ocr_pin')
            version=subprocess.run([str(path),'--version'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL,timeout=5,check=True).stdout
            C.require(version.splitlines()[0]==b'tesseract 5.5.0','ocr_pin')
        except (OSError,subprocess.SubprocessError):raise C.Rejected('ocr_pin') from None
        self.binary=str(path)
    def read(self,frame,rect,deadline_ns):
        x0,y0,x1,y1=rect
        C.require(0<=x0<x1<=1280 and 0<=y0<y1<=800,'ocr')
        pixels=frame.bgra();ppm=bytearray(f'P6\n{x1-x0} {y1-y0}\n255\n','ascii')
        for y in range(y0,y1):
            for x in range(x0,x1):
                offset=(y*1280+x)*4;ppm.extend((pixels[offset+2],pixels[offset+1],pixels[offset]))
        try:
            remaining=min(10,(deadline_ns-time.monotonic_ns())/1e9);C.require(remaining>0,'deadline')
            return bounded_ocr_process([self.binary,'stdin','stdout','--psm','6','-l','eng'],ppm,
                                       min(deadline_ns,time.monotonic_ns()+10_000_000_000))
        except (OSError,UnicodeError,subprocess.SubprocessError):raise C.Rejected('ocr') from None
        finally:
            for i in range(len(ppm)):ppm[i]=0

def actual_approval_line(rendered):
    """Extract exactly one actual rendered challenge, never infer/reconstruct it."""
    C.require(type(rendered) is str and len(rendered)<=32768,'ocr_prompt')
    matches=re.findall(r'Type (APPROVE [0-9a-f]{16}) to approve this exact operation,',rendered)
    C.require(len(matches)==1,'ocr_prompt');return matches[0]
