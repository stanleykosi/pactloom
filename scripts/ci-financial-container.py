#!/usr/bin/env python3
"""Single-use financial qualification PID1. Only an isolated pinned rootfs.

Private fixture/Host bytes never reach stdout. The final inner candidate is not
public success until the outer owner proves rootfs/container removal.
"""
import ctypes
import contextlib
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import resource
import re
import selectors
import signal
import stat
import ssl
import subprocess
import sys
import tempfile
import time
ROOT=pathlib.Path(__file__).resolve().parent

def load(name):
    key=name.replace('-','_')
    if key in sys.modules:return sys.modules[key]
    spec=importlib.util.spec_from_file_location(key,ROOT/(name+'.py'))
    obj=importlib.util.module_from_spec(spec);sys.modules[key]=obj;spec.loader.exec_module(obj);return obj
FLOW=load('ci-financial-flow');S=FLOW.S;C=S.C;F=S.F;K=S.K
OBS=load('ci-financial-observer');OUT=load('ci-financial-external-output');EXT=load('ci-financial-external-operator')
UID=10001
EVIDENCE=pathlib.Path('/ci-financial-evidence')
WAYLAND=pathlib.Path('/run/ci-financial-wayland')
FIXTURE=pathlib.Path('/ci-fixture/full-parent')
PROVIDER_CA=pathlib.Path('/etc/wholepact/fixture-provider-ca.pem')
PROVIDER_CA_LINK=pathlib.Path('/etc/ssl/certs/wholepact-fixture-provider.pem')
PARENT_SELECTOR=('host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::'
 'qualification::durable_proposal_v1::coordinated_full_fixture_v1::coordinator_live_full_financial_fixture_parent')
READY=b'CI_FINANCIAL_FIXTURE_READY version=1'
CLEANED=b'CI_FINANCIAL_FIXTURE_CLEANED version=1'
DIAGNOSTIC=b'CI_FINANCIAL_FIXTURE_DIAGNOSTIC '
FIXTURE_PHASES=frozenset(('child_identity','child_directory','child_exec','core_policy','wait_policy',
    'cutoff','parent_directory','temporary_root','tls_material','child_stage','cleanup','cleanup_record','completion',
    'post_final_inspection','post_input_entry','post_anchor_drain','post_source_one_open','post_source_one_metadata','post_source_one_preserve','post_source_two_open','post_source_two_metadata','post_source_two_preserve','post_signer_shutdown','post_host_fence','post_witness_descriptor','post_handoff_write','post_external_controls','post_external_bootstrap','post_ready'))
FIXTURE_REASONS=frozenset(('Setup','Unclassified','Deadline','ChildObservation','ChildExit','PollIo','ReadIo',
    'OutputLimit','IncompleteUtf8','InvalidUtf8','MultilineInput','WriteIo','FlushIo','MissingPathMarker',
    'InvalidPath','InvalidChallenge','OutcomeRead','CleanupUnverified','FinancialPhaseDeadline','FinancialProgressInvalid'))

def fixture_diagnostic(line):
    """Only a complete exact closed diagnostic can cross the private stdout boundary."""
    C.require(type(line) is bytes and line.startswith(DIAGNOSTIC) and len(line)<=2048,'fixture')
    value=C.loads(line[len(DIAGNOSTIC):],2048)
    C.exact(value,('version','phase','reason','next','expected','process_cleanup','root_cleanup'))
    C.require(type(value['version']) is int and value['version']==1 and
        type(value['phase']) is str and value['phase'] in FIXTURE_PHASES and
        type(value['reason']) is str and value['reason'] in FIXTURE_REASONS and
        type(value['next']) is int and type(value['expected']) is int and
        0<=value['next']<=value['expected']<=4096 and
        type(value['process_cleanup']) is bool and type(value['root_cleanup']) is bool,'fixture')
    return value

def emit_fixture_diagnostic(value):
    # Re-encode validated fields, never echo the source line or exception.
    value=fixture_diagnostic(DIAGNOSTIC+json.dumps(value,separators=(',',':')).encode('utf-8'))
    print(DIAGNOSTIC.decode('ascii')+json.dumps(value,separators=(',',':')),flush=True)

OCR_SHA='74b76a5b994adcc18be362bf64ed5118082b2401d5d9a35242e92fc4c62e2b4b'
RUNTIME_FILES=('ci-financial-container.py','ci-financial-flow.py','ci-financial-scenario.py','ci-financial-host-context.py',
 'ci-financial-contract.py','ci-financial-fixture.py','ci-financial-controller.py',
 'ci-financial-observer.py','ci-financial-output.py','ci-financial-external-output.py',
 'ci-financial-external-operator.py','ci-financial-weston-module.so')
ARTIFACTS=('coordinator-observed','coordinator-production','pristine-setup')


def secure_file(path,owner,mode,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        m=os.fstat(stream.fileno())
        C.require(stat.S_ISREG(m.st_mode) and m.st_uid==owner and m.st_nlink==1 and
                  stat.S_IMODE(m.st_mode)==mode and 0<m.st_size<=limit,'fixture_path')
        raw=stream.read(limit+1);C.require(len(raw)==m.st_size,'fixture_path')
        return raw,m

@contextlib.contextmanager
def fixture_effective_identity():
    """Read only private ordinary metadata as its owner, never add DAC caps.

    Used solely before the permanent drop, while single-threaded. Root writes
    only public account/common-image metadata after the original IDs return.
    """
    C.require(os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0) and
              len(list(pathlib.Path('/proc/self/task').iterdir()))==1,'process')
    os.setgroups([])
    os.setresgid(-1,UID,-1)
    try:
        os.setresuid(-1,UID,-1)
        try:
            C.require(os.getresuid()==(0,UID,0) and os.getresgid()==(0,UID,0) and not os.getgroups(),'process')
            yield
        finally:os.setresuid(-1,0,-1)
    finally:os.setresgid(-1,0,-1)
    C.require(os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0),'process')

def root_setup():
    C.require(ROOT==pathlib.Path('/opt/ci-financial') and os.getpid()==1 and
              os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0),'process')
    C.require(len(list(pathlib.Path('/proc/self/task').iterdir()))==1,'process')
    status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
    C.require(all(int(status[k],16)==0xc0 for k in ('CapEff','CapPrm','CapBnd')) and
              all(int(status[k],16)==0 for k in ('CapInh','CapAmb')) and status['NoNewPrivs'].strip()=='1','process')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    libc=ctypes.CDLL(None,use_errno=True);C.require(libc.prctl(4,0,0,0,0)==0,'process')
    os.environ.clear()
    raw,_=secure_file(ROOT/'manifest.json',0,0o444,32768);manifest=C.loads(raw,32768)
    C.exact(manifest,('schema','profile','source_commit','files'))
    C.require(manifest['schema']==1 and manifest['profile'] in (C.EXTERNAL_PROFILE,C.SEMANTIC_PROFILE) and
              type(manifest['source_commit']) is str and len(manifest['source_commit'])==40 and
              set(manifest['files'])==set(RUNTIME_FILES+ARTIFACTS),'contract')
    observed=None
    for name,pin in manifest['files'].items():
        C.exact(pin,('size','sha256'))
        mode=0o555 if name in ARTIFACTS else 0o444
        raw,meta=secure_file(ROOT/name,UID if name=='pristine-setup' else 0,mode,512*1024*1024)
        C.require(len(raw)==pin['size'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],'contract')
        if name=='coordinator-observed':observed=(meta,pin['sha256'])
    with fixture_effective_identity():
        for path in (pathlib.Path('/ci-fixture'),EVIDENCE,WAYLAND,EXT.CONTROL):
            m=path.stat(follow_symlinks=False)
            C.require(stat.S_ISDIR(m.st_mode) and m.st_uid==UID and m.st_gid==UID and
                      stat.S_IMODE(m.st_mode)==0o700 and not list(path.iterdir()),'fixture_path')
    # Root writes only the fixed common-image pin and public account metadata.
    # It never opens either synthetic password file.
    meta,digest=observed
    pin={'schema_version':1,'profile':'financial-coordinator-common-image-linux-v1',
         'executable_device':meta.st_dev,'executable_inode':meta.st_ino,
         'executable_size':meta.st_size,'executable_sha256':digest}
    write_new(pathlib.Path('/etc/wholepact/financial-coordinator-common-image-v1.json'),json.dumps(pin).encode(),0o444)
    base,_=secure_file(ROOT/'base-passwd',0,0o444,65536)
    write_account(base,'/nonexistent',initial=True)
    return base,manifest['profile']

def write_new(path,data,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),mode);stream.write(data)

def read_fixture_provider_ca(selected):
    """Only the original fixture's public CA, through no-follow directory FDs."""
    selected=F.absolute(str(selected));root=selected.parent
    C.require(selected.name==F.FIXTURE_FILE and root.parent==F.ARTIFACT_PARENT and
              root.name.startswith('f-') and len(root.name)>2,'fixture_path')
    directory=root/'synthetic-provider-tls-v1'
    private={F.ARTIFACT_PARENT.parent,F.ARTIFACT_PARENT,root,directory}
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        current=pathlib.Path('/')
        for part in directory.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child;current=current/part
            if current in private:
                meta=os.fstat(fd)
                C.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid==UID and meta.st_gid==UID and
                          stat.S_IMODE(meta.st_mode)==0o700,'fixture_path')
        leaf=os.open('ca.pem',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        with os.fdopen(leaf,'rb') as stream:
            before=os.fstat(stream.fileno())
            C.require(stat.S_ISREG(before.st_mode) and before.st_uid==UID and before.st_gid==UID and
                      before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and
                      0<before.st_size<=16384,'fixture_path')
            raw=stream.read(16385);after=os.fstat(stream.fileno())
            stable=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            C.require(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in stable),'fixture_path')
            return raw
    finally:os.close(fd)

def validate_fixture_provider_ca(raw):
    # No general certificate input: exactly the generated public root, never a
    # key, chain, appended block or arbitrary trailing text.
    C.require(type(raw) is bytes and 0<len(raw)<=16384 and
        re.fullmatch(rb'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n',raw) is not None,'fixture')
    try:
        pem=raw.decode('ascii')
        der=base64.b64decode(b''.join(raw.splitlines()[1:-1]),validate=True)
        C.require(der==ssl.PEM_cert_to_DER_cert(pem),'fixture')
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        original=set(context.get_ca_certs(binary_form=True))
        context.load_verify_locations(cadata=pem)
        certificates=context.get_ca_certs(binary_form=True)
        C.require(der in certificates and set(certificates)==original|{der},'fixture')
        cert=context.get_ca_certs()[certificates.index(der)]
        C.require(cert['subject']==cert['issuer'],'fixture')
    except (ValueError,ssl.SSLError,KeyError,IndexError):
        raise C.Rejected('fixture') from None

def install_fixture_provider_ca(selected,deadline):
    """Public test trust only, inside the existing disposable root-owned tmpfs."""
    C.require(os.getpid()==1 and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0),'process')
    directory=PROVIDER_CA.parent
    meta=directory.lstat();link=PROVIDER_CA_LINK.lstat()
    C.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid==0 and meta.st_gid==0 and
              stat.S_IMODE(meta.st_mode)==0o755 and stat.S_ISLNK(link.st_mode) and
              link.st_uid==0 and os.readlink(PROVIDER_CA_LINK)==str(PROVIDER_CA) and
              not os.path.lexists(PROVIDER_CA),'contract')
    with fixture_effective_identity():raw=read_fixture_provider_ca(selected)
    validate_fixture_provider_ca(raw)
    # OpenSSL sees only an unlinked public copy. The final native trust path is
    # still absent until strict self-signature and validity verification pass.
    with tempfile.TemporaryFile(dir=directory) as public:
        public.write(raw);public.flush();public.seek(0)
        name='/proc/self/fd/'+str(public.fileno())
        left=(deadline-time.monotonic_ns())/1e9;C.require(left>0,'fixture_deadline')
        result=subprocess.run(['/usr/bin/openssl','verify','-x509_strict','-check_ss_sig',
            '-CAfile',name,'-no-CApath','-no-CAstore',name],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            close_fds=True,pass_fds=(public.fileno(),),env={},timeout=left,check=False)
        C.require(result.returncode==0,'fixture')
    C.require(time.monotonic_ns()<deadline,'fixture_deadline')
    fd=os.open(PROVIDER_CA,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),0o444);stream.write(raw);stream.flush();os.fsync(stream.fileno())
        C.require(time.monotonic_ns()<deadline,'fixture_deadline')
    except BaseException as error:
        try:PROVIDER_CA.unlink()
        except OSError:
            # Never continue to native launch or claim this partial file gone.
            # The original failure survives; outer tmpfs removal is mandatory.
            error.fixture_trust_cleanup_unverified=True
        raise

def write_account(base,home,*,initial=False):
    F.absolute(home);C.require(':' not in home and '\n' not in home,'fixture_path')
    lines=base.decode('ascii').splitlines()
    C.require(all(len(line.split(':'))==7 and line.split(':')[0]!='wholepact-ci' and
                  line.split(':')[2]!=str(UID) for line in lines),'contract')
    target=pathlib.Path('/run/ci-account/passwd')
    C.require(pathlib.Path('/etc/passwd').is_symlink() and os.readlink('/etc/passwd')==str(target),'contract')
    data=base+f'wholepact-ci:x:{UID}:{UID}:Disposable CI fixture:{home}:/usr/sbin/nologin\n'.encode()
    temporary=pathlib.Path('/run/ci-account/passwd.initial' if initial else '/run/ci-account/passwd.final')
    write_new(temporary,data,0o444);os.replace(temporary,target)

class FixtureParent:
    def __init__(self,deadline):
        self.deadline=deadline;self.pending=bytearray();self.total=0;self.process=None;self.diagnostic=None
        # Root does not create/chown inside the UID-only fixture tmpfs. The
        # exact child creates its TMPDIR under its already assigned identity.
        self.process=subprocess.Popen(['/usr/local/bin/python3','-I','-B',str(ROOT/'ci-financial-container.py'),'fixture-child'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,
            user=UID,group=UID,extra_groups=[],start_new_session=True,env={})
        self.wait_marker(READY)
        with fixture_effective_identity():
            raw,_=secure_file(FIXTURE/'coordinated-financial-ready-v1.json',UID,0o600,16384)
            pointer=C.loads(raw,16384);C.exact(pointer,('version','fixture_path','original_monotonic_cutoff_ns'))
            C.require(pointer['version']==1 and time.monotonic_ns()<pointer['original_monotonic_cutoff_ns']<=deadline,'fixture_deadline')
            self.deadline=pointer['original_monotonic_cutoff_ns'];self.path=F.absolute(pointer['fixture_path'])
            raw,_=secure_file(self.path,UID,0o600,1024*1024)
            metadata=C.loads(raw,1024*1024);self.home=F.absolute(metadata['witness']['home_path'])
    def wait_marker(self,marker):
        with selectors.DefaultSelector() as sel:
            sel.register(self.process.stdout,selectors.EVENT_READ)
            while True:
                left=(self.deadline-time.monotonic_ns())/1e9;C.require(left>0,'fixture_deadline')
                ready=sel.select(left);C.require(ready,'fixture_deadline')
                block=os.read(self.process.stdout.fileno(),32768);C.require(block,'fixture')
                self.total+=len(block);C.require(self.total<=1024*1024,'record_limit');self.pending.extend(block)
                while b'\n' in self.pending:
                    line,_,tail=self.pending.partition(b'\n');self.pending=bytearray(tail)
                    line=bytes(line.rstrip(b'\r'))
                    if line.startswith(DIAGNOSTIC):
                        C.require(self.diagnostic is None,'fixture')
                        self.diagnostic=fixture_diagnostic(line)
                        emit_fixture_diagnostic(self.diagnostic)
                        C.require(False,'fixture')
                    if line==marker:return
    def finish(self,normal):
        C.require(self.process.poll() is None,'cleanup')
        line=b'FINISH\n' if normal else b'CANCEL\n'
        C.require(os.write(self.process.stdin.fileno(),line)==len(line),'cleanup')
        self.process.stdin.close();self.wait_marker(CLEANED)
        C.require(self.process.wait(timeout=max(.001,(self.deadline-time.monotonic_ns())/1e9))==0,'cleanup')

class NativeSession:
    def __init__(self,fixture,deadline,expected_profile=C.EXTERNAL_PROFILE):
        self.deadline=min(deadline,fixture.deadline_ns);self.fixture=fixture
        self.observer=OBS.ObserverFiles(EVIDENCE,self.deadline,expected_profile)
        self.operator=EXT.ExternalOperator()
        self.controller,edge,additions=K.make_channel(deadline,self.deadline)
        try:
            self.weston=subprocess.Popen(['/usr/bin/weston','--backend=headless','--renderer=pixman',
              '--shell=kiosk-shell.so','--width=1280','--height=800','--scale=1','--transform=normal',
              '--socket=wayland-financial','--idle-time=0','--no-config',
              '--modules=/opt/ci-financial/ci-financial-weston-module.so'],
              stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
              close_fds=True,pass_fds=(edge.fileno(),),start_new_session=True,
              env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8','XDG_RUNTIME_DIR':str(WAYLAND),**additions})
        finally:edge.close()
        self.controller.wait_ready()
        env={'XDG_RUNTIME_DIR':str(WAYLAND),'WAYLAND_DISPLAY':'wayland-financial'}
        K.check_product_environment(env)
        self.product=subprocess.Popen([str(ROOT/'coordinator-observed')],stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,pass_fds=(),env=env,start_new_session=True)
        self.controller.bind_process(self.product);self.controller.focus(True)
    def run(self):
        ocr=None if self.observer.expected_profile==C.SEMANTIC_PROFILE else S.PinnedLocalOcr('/usr/bin/tesseract',OCR_SHA)
        self.flow=FLOW.FullFlow(self.controller,self.fixture,self.observer,ocr,self.operator)
        self.flow.run()
        status=self.product.wait(timeout=max(.001,(self.deadline-time.monotonic_ns())/1e9))
        return self.observer.read(final=True),self.product.pid,status
    def finish_display(self):
        if self.weston.poll() is None:self.weston.terminate()
        status=self.weston.wait(timeout=5)
        self.controller.finish_after_product(status,min(self.deadline,time.monotonic_ns()+5_000_000_000))

def fixture_child():
    phase='child_identity'
    try:
        C.require(os.getresuid()==(UID,UID,UID) and os.getresgid()==(UID,UID,UID) and not os.getgroups(),'process')
        phase='child_directory'
        FIXTURE.mkdir(mode=0o700)
        phase='child_exec'
        os.execve(ROOT/'pristine-setup',[str(ROOT/'pristine-setup'),'--exact',PARENT_SELECTOR,'--ignored','--nocapture','--test-threads=1'],
                  {'PATH':'/usr/bin:/bin','TMPDIR':str(FIXTURE),'LANG':'C.UTF-8','RUST_BACKTRACE':'0'})
    except BaseException:
        emit_fixture_diagnostic({'version':1,'phase':phase,'reason':'Setup','next':0,'expected':0,
                                 'process_cleanup':False,'root_cleanup':False})
        raise SystemExit(1) from None

def emit_cached_progress_failure(flow):
    # Only called on failure. No fresh observation or private record is emitted.
    # A rejected diagnostic must not replace the original failure result.
    if flow is None:return
    try:
        value=flow.observer.failure_diagnostics()['progress']
        if value is None:return
        encoded=json.dumps(C.validate_progress_diagnostic(value),separators=(',',':'))
    except Exception:return
    print('CI_FINANCIAL_PROGRESS_DIAGNOSTIC '+encoded,flush=True)


def emit_cached_host_failure(flow):
    if flow is None:return
    try:
        value=flow.host_diagnostic()
        encoded=json.dumps(C.validate_host_diagnostic(value),separators=(',',':'))
        print('CI_FINANCIAL_HOST_DIAGNOSTIC '+encoded,flush=True)
    except Exception:return # best effort; preserve original failure and cleanup


def emit_cached_review_failure(flow):
    if flow is None:return
    try:
        value=flow.review_diagnostic()
        if value is None:return
        encoded=json.dumps(C.validate_review_diagnostic(value),separators=(',',':'))
        print('CI_FINANCIAL_REVIEW_DIAGNOSTIC '+encoded,flush=True)
    except Exception:return # No failure/result/cleanup replacement.


def emit_cached_native_failure(flow):
    # No new read/clock/input here; unavailable cached evidence stays unavailable.
    if flow is None or flow.expected_profile!=C.SEMANTIC_PROFILE:return
    try:
        value=flow.observer.failure_diagnostics()['native']
        encoded=json.dumps(C.validate_native_failure_diagnostic(value),separators=(',',':'))
        print('CI_FINANCIAL_NATIVE_FAILURE_DIAGNOSTIC '+encoded,flush=True)
    except Exception:return # never replace the original failure or cleanup


def emit_cached_observation_timing_failure(flow):
    if flow is None:return
    try:
        value=flow.observer.failure_diagnostics()['timing']
        encoded=json.dumps(C.validate_observation_timing_diagnostic(value),separators=(',',':'))
        print('CI_FINANCIAL_OBSERVATION_TIMING_DIAGNOSTIC '+encoded,flush=True)
    except Exception:return # preserve original failure; no late collection


def emit_cached_host_exit_failure(flow):
    if flow is None or flow.expected_profile!=C.SEMANTIC_PROFILE:return
    try:
        value=flow.observer.failure_diagnostics()['host_exit']
        encoded=json.dumps(C.validate_host_exit_diagnostic(value),separators=(',',':'))
        print('CI_FINANCIAL_HOST_EXIT_DIAGNOSTIC '+encoded,flush=True)
    except Exception:return # independent cached actors, no late IO or inference


def emit_cached_actor_failure(flow):
    if flow is None or flow.expected_profile!=C.SEMANTIC_PROFILE:return
    try:
        value=flow.observer.failure_diagnostics()['actor']
        encoded=json.dumps(C.validate_actor_diagnostic(value),separators=(',',':'))
        print('CI_FINANCIAL_ACTOR_DIAGNOSTIC '+encoded,flush=True)
    except Exception:return # Cached validated slots only; preserve failure/cleanup.


def emit_cached_input_failure(flow,error):
    # Original exception and cached checkpoint only; no fresh read/input/clock.
    try:
        budget=getattr(error,'input_budget',None)
        if budget is not None:
            value=dict(version=1,budget=budget,last_main_loop=getattr(flow,'input_checkpoint',None))
        elif getattr(error,'code',None)=='input_disabled' and getattr(error,'input_guard',None) is not None:
            value=dict(version=2,guard=error.input_guard)
        else:return
        encoded=json.dumps(C.validate_input_diagnostic(value),separators=(',',':'))
        print('CI_FINANCIAL_INPUT_DIAGNOSTIC '+encoded,flush=True)
    except Exception:return



def emit_snapshot_failure(error):
    # Exception-local finite reason only, never raw errors, records or new reads.
    try:
        if getattr(error,'code',None)!='snapshot':return
        value=dict(version=1,reason=getattr(error,'snapshot_reason','Unclassified'))
        encoded=json.dumps(C.validate_snapshot_diagnostic(value),separators=(',',':'))
        print('CI_FINANCIAL_SNAPSHOT_DIAGNOSTIC '+encoded,flush=True)
    except Exception:return # Preserve the original failure and cleanup.


def main():
    if sys.argv[1:]==['fixture-child']:fixture_child();return
    C.require(not sys.argv[1:],'contract')
    original=time.monotonic_ns()+C.ORIGINAL_NS
    parent=session=None
    expected_profile=C.EXTERNAL_PROFILE
    try:
        base,expected_profile=root_setup();parent=FixtureParent(original)
        install_fixture_provider_ca(parent.path,parent.deadline)
        write_account(base,str(parent.home))
        os.setgroups([]);os.setresgid(UID,UID,UID);os.setresuid(UID,UID,UID);K.harden_process()
        fixture=F.Fixture.load(parent.path,original,expected_profile)
        session=NativeSession(fixture,original,expected_profile);records,pid,status=session.run()
        parent.finish(True)
        cleanup_raw,_=secure_file(FIXTURE/'coordinated-financial-cleanup-v1.json',UID,0o600,16384)
        external=session.operator.evidence(C.loads(cleanup_raw,16384),parent.process.pid,parent.process.returncode)
        evidence=OUT.validate_completed(records,pid,status,external,expected_profile)
        session.finish_display()
        C.require({int(p.name) for p in pathlib.Path('/proc').iterdir() if p.name.isdecimal()}=={1},'cleanup')
        # Outer rootfs owner MUST verify removal before translating candidate
        # into public_result; this marker itself is not a qualification pass.
        print('CI_FINANCIAL_CANDIDATE '+json.dumps({'schema':1,'profile':expected_profile,
              'native_oracle_verified':True,'fixture_cleaned':True,'display_cleaned':True,
              'public_chain_verified':False,'dispatch_attempted':False},separators=(',',':')),flush=True)
    except BaseException as error:
        code=getattr(error,'code','process')
        flow=getattr(session,'flow',None)
        # LOCATION is the last validated main-loop nonterminal checkpoint only; omit it
        # when none was observed. It does not identify the terminal cause.
        if flow is not None and flow.location is not None:
            print('CI_FINANCIAL_LOCATION '+json.dumps(flow.location,separators=(',',':')),flush=True)
        emit_cached_input_failure(flow,error)
        emit_snapshot_failure(error)
        emit_cached_progress_failure(flow)
        emit_cached_host_failure(flow)
        emit_cached_review_failure(flow)
        emit_cached_native_failure(flow)
        emit_cached_observation_timing_failure(flow)
        emit_cached_host_exit_failure(flow)
        emit_cached_actor_failure(flow)
        # No raw exception/path/Host output escapes. Outer owner destroys whole
        # isolated namespace on failure; never report rescue cleanup as normal.
        print('CI_FINANCIAL_RESULT '+json.dumps(OUT.failure(code,expected_profile),separators=(',',':')),flush=True)
        raise SystemExit(1) from None

if __name__=='__main__':main()
