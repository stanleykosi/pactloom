"""Pure cross-feature checks: no product, compositor, or actual credentials."""
import contextlib
import io
import json
import pathlib
import unittest
from unittest import mock
import test_ci_financial_observer as O
import test_ci_financial_input_batching as B
import test_ci_financial_fixture_diagnostics as D
F=O.F

class ComposedStartupTests(unittest.TestCase):
    def setUp(self):
        self.startup=O.HostStartupContractTests();self.startup.setUp()
        self.addCleanup(self.startup.doCleanups)
    def test_long_owned_writing_does_not_spend_idle_sweep_or_source_actions(self):
        flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP);flow.startup_waiting=True
        flow.startup_focus_seen=True;flow.last_phase=('Selecting','None',None)
        key=('Selecting','None','idle_sweep',None);flow.scrolls[key]=63
        base=O.observed_snapshot(phase='Selecting',subphase='None',owner=None,focused=True,secret_input=False,widgets=[])
        flow.snapshot=mock.Mock(side_effect=[base|{'host_input':True}]*200+[base|{'host_input':False}])
        flow.idle_scan=mock.Mock(side_effect=AssertionError('no outer scan while startup owns Writing'))
        def source(*args):
            self.assertTrue(flow.host_startup_complete)
            self.assertEqual(flow.scrolls[key],63)
            raise F.C.Rejected('missing_evidence')
        flow.save_selector=mock.Mock(side_effect=source)
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'missing_evidence')
        self.assertEqual(flow.controller.wait_render_progress.call_count,200)
        flow.save_selector.assert_called_once();flow.idle_scan.assert_not_called()
        flow.controller.click.assert_not_called();flow.controller.scroll_up.assert_not_called()
        flow.controller.scroll_down.assert_not_called();self.assertEqual(flow.scrolls[key],63)
    def test_poststartup_writing_in_selecting_and_waiting_never_scrolls_captures_or_inputs(self):
        for phase,owner in (('Selecting',None),('Waiting','Signer1'),('SetupNeeded','Signer1'),('AdmissionReview','Signer2')):
            with self.subTest(phase=phase):
                flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP)
                flow.startup_focus_seen=True
                base=O.observed_snapshot(phase=phase,subphase='None',owner=owner,focused=True,secret_input=False,host_input=True,widgets=[])
                flow.snapshot=mock.Mock(side_effect=[base]*100+[base|{'phase':'Revoked','host_input':False}])
                flow.save_selector=mock.Mock(side_effect=AssertionError('source effect while Host Writing'))
                flow.paired_admission=mock.Mock(side_effect=AssertionError('paired review while Host Writing'))
                flow.idle_scan=mock.Mock(side_effect=AssertionError('scroll while Host Writing'))
                flow.native.capture_host=mock.Mock(side_effect=AssertionError('capture while Host Writing'))
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,'source_failure')
                self.assertEqual(flow.controller.wait_render_progress.call_count,100)
                flow.save_selector.assert_not_called();flow.idle_scan.assert_not_called()
                flow.paired_admission.assert_not_called()
                flow.native.capture_host.assert_not_called();flow.controller.click.assert_not_called()
                self.assertEqual(flow.actions,0);self.assertEqual(flow.scrolls,{})
    def test_source_password_branch_remains_separate_and_preserved(self):
        flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP)
        flow.fixture=mock.Mock();secret=mock.Mock();flow.fixture.secret.return_value=secret
        snapshot=O.observed_snapshot(phase='V3Password',subphase='None',owner='Signer1',focused=True,
                      secret_input=True,host_input=False,widgets=[])
        flow.snapshot=mock.Mock(side_effect=[snapshot,snapshot,snapshot|{'phase':'Revoked'}])
        flow.native.protected_input=mock.Mock();flow.press=mock.Mock();flow.password_seek=mock.Mock(side_effect=lambda value,tag:value)
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'source_failure')
        flow.fixture.secret.assert_called_once_with('source')
        flow.native.protected_input.assert_called_once_with('V3Password','Signer1','SourcePassword',secret,source_context=(0,0))
        secret.wipe.assert_called_once_with()
        flow.press.assert_called_once_with(snapshot,'PasswordSubmit','Signer1')
        flow.controller.wait_render_progress.assert_not_called()
    def test_unexpected_source_secret_flag_rejects_before_any_host_or_source_effect(self):
        for phase,owner in (('Selecting',None),('Waiting','Signer1'),('AdmissionReview','Signer2'),('V3Configuring','Signer1')):
            with self.subTest(phase=phase):
                flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP)
                snapshot=O.observed_snapshot(phase=phase,subphase='None',owner=owner,focused=True,
                              secret_input=True,host_input=False,widgets=[])
                flow.snapshot=mock.Mock(return_value=snapshot)
                flow.pump_host=mock.Mock(side_effect=AssertionError('unexpected protected Host work'))
                flow.idle_scan=mock.Mock();flow.review=mock.Mock();flow.paired_admission=mock.Mock()
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,'input_phase')
                flow.pump_host.assert_not_called();flow.idle_scan.assert_not_called()
                flow.review.assert_not_called();flow.paired_admission.assert_not_called()
                self.assertEqual(flow.controller.mock_calls,[])
                self.assertEqual(self.startup.fixture.secret_instances,[])

    def test_native_source_entry_intent_frame_waits_only_after_exact_consumed_action(self):
        native=(O.ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
        finish=native.index('if crate::financial_ci::finish(')
        self.assertIn('self.password.is_some() || matches!(self.intent, Some(Intent::PasswordV3 | Intent::EnterPassword))',native[finish:finish+400])
        self.assertLess(finish,native.index('let intent = self.intent.take();',finish))
        self.assertIn('Intent::PasswordV3 if self.phase == Phase::V3Confirm',native)
        self.assertIn('Intent::EnterPassword if self.phase == Phase::EntryConfirm',native)
        for phase,action,next_phase in (('V3Confirm','PasswordV3','V3Password'),('EntryConfirm','EnterPassword','Password')):
            for owner in ('Signer1','Signer2'):
                with self.subTest(phase=phase,owner=owner):
                    flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP)
                    snapshot=O.observed_snapshot(phase=phase,subphase='None',owner=owner,focused=True,secret_input=True,host_input=False,widgets=[])
                    flow.done.add(flow.key(snapshot,action,owner)+(None,))
                    entered=snapshot|{'phase':next_phase}
                    flow.snapshot=mock.Mock(side_effect=[snapshot,entered,entered,entered|{'phase':'Revoked'}])
                    flow.fixture=mock.Mock();secret=mock.Mock();flow.fixture.secret.return_value=secret
                    flow.native.protected_input=mock.Mock();flow.press=mock.Mock();flow.password_seek=mock.Mock(side_effect=lambda value,tag:value)
                    flow.pump_host=mock.Mock();flow.idle_scan=mock.Mock()
                    with self.assertRaises(F.C.Rejected) as error:flow.run()
                    self.assertEqual(error.exception.code,'source_failure')
                    flow.controller.wait_render_progress.assert_called_once_with()
                    flow.native.protected_input.assert_called_once_with(next_phase,owner,'SourcePassword',secret,source_context=(0,0))
                    secret.wipe.assert_called_once_with()
                    flow.press.assert_called_once_with(entered,'PasswordSubmit',owner)
                    flow.pump_host.assert_not_called();flow.idle_scan.assert_not_called()
    def test_unowned_or_mismatched_source_entry_protected_frame_fails_without_effects(self):
        for phase,action in (('V3Confirm','PasswordV3'),('EntryConfirm','EnterPassword')):
            for mismatch in ('unowned','owner','phase','subphase','action','host_overlap'):
                with self.subTest(phase=phase,mismatch=mismatch):
                    flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP)
                    old=O.observed_snapshot(phase=phase,subphase='None',owner='Signer1',focused=True,secret_input=True,host_input=False,widgets=[])
                    if mismatch!='unowned':flow.done.add(flow.key(old,'Read' if mismatch=='action' else action,'Signer1')+(None,))
                    changes={'owner':{'owner':'Signer2'},'phase':{'phase':'Waiting'},'subphase':{'subphase':'ReadReview'},'host_overlap':{'host_input':True}}.get(mismatch,{})
                    flow.snapshot=mock.Mock(return_value=old|changes)
                    flow.pump_host=mock.Mock();flow.idle_scan=mock.Mock();flow.press=mock.Mock()
                    with self.assertRaises(F.C.Rejected) as error:flow.run()
                    self.assertEqual(error.exception.code,'input_phase')
                    self.assertEqual(flow.controller.mock_calls,[])
                    flow.pump_host.assert_not_called();flow.idle_scan.assert_not_called();flow.press.assert_not_called()

    def test_incomplete_informational_tail_yields_source_after_finite_actual_wheels(self):
        flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP)
        text=':'
        h=dict(revision=1,nonws_end=100,context_valid=True,entry='Idle',editor=None,
               view=dict(rect=[10,200,110,220],nonws=F.H.count(text),rows=1))
        snapshot=O.observed_snapshot(phase='Selecting',subphase='None',owner=None,focused=True,
            secret_input=False,host_input=False,host_observation=h,view_generation=1,
            pixels_per_point=1,viewport=[1280,800],widgets=[
                dict(tag=tag,owner=None,rect=[10,y,110,y+20],enabled=True)
                for tag,y in (('BeginHostLine',100),('HostOutput',200),('ScrollRegion',400))])
        F.C.validate_snapshot(snapshot)
        flow.snapshot=mock.Mock(return_value=snapshot)
        flow.native.stable=mock.Mock(return_value=snapshot)
        flow.native.capture_host=mock.Mock(return_value=(text,h))
        def source(*args):
            self.assertEqual(flow.host_coverage_steps,16)
            raise F.C.Rejected('missing_evidence')
        flow.save_selector=mock.Mock(side_effect=source)
        with mock.patch.object(F.time,'monotonic_ns',return_value=10_000_000_000):
            with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'missing_evidence')
        self.assertEqual(flow.controller.scroll_up.call_count,8)
        self.assertEqual(flow.controller.scroll_down.call_count,8)
        flow.native.capture_host.assert_called_once();flow.controller.click.assert_not_called()
        flow.save_selector.assert_called_once();self.assertEqual(flow.host_occurrences.attempts,0)

    def test_later_owned_host_lines_never_reenter_startup_through_editing_writing_idle(self):
        cases=(('SetupNeeded','Signer1','synthetic-continuation.json'),
               ('SignCommitted','Signer2','synthetic-result.json'),
               ('Waiting','Signer1','coordinated-reviewer-selection-1.json'),
               ('ReturnReadReview','Signer2','APPROVE 0123456789abcdef'))
        for phase,owner,value in cases:
            with self.subTest(phase=phase,owner=owner):
                flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP);flow.startup_focus_seen=True
                flow.host_lines=14;flow.pending_host=('public',value);flow.pending_occurrence=(100,120,2)
                flow.host_occurrences.latch(flow.pending_occurrence)
                h=dict(revision=2,nonws_end=120,context_valid=True,entry='Editing',view=None,
                       editor=dict(ordinal=14,revision=2))
                editing=O.observed_snapshot(phase=phase,owner=owner,subphase='None',focused=True,
                    host_input=True,secret_input=False,host_observation=h,view_generation=1,
                    pixels_per_point=1,viewport=[1280,800],widgets=[
                        dict(tag=tag,owner=None,enabled=True,rect=[10,y,110,y+20])
                        for tag,y in (('HostEditor',100),('HostSubmit',150))])
                editing['widgets'].append(dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,800]))
                F.C.validate_snapshot(editing)
                writing=editing|{'host_observation':h|{'entry':'Writing','editor':None},'widgets':[]}
                idle=writing|{'host_input':False,'host_observation':h|{'entry':'Idle','editor':None}}
                snapshots=iter((editing,editing,writing,writing,idle));current=[None]
                def snapshot():
                    self.assertTrue(flow.host_startup_complete)
                    current[0]=next(snapshots);return current[0]
                flow.snapshot=snapshot;flow.native.stable=mock.Mock(return_value=editing)
                def source(*args,**kwargs):
                    self.assertTrue(flow.host_startup_complete)
                    self.assertFalse(current[0]['host_input']);self.assertEqual(current[0]['host_observation']['entry'],'Idle')
                    raise F.C.Rejected('missing_evidence')
                flow.save_selector=mock.Mock(side_effect=source)
                flow.idle_scan=mock.Mock(side_effect=source);flow.review=mock.Mock(side_effect=source)
                flow.native.capture_host=mock.Mock(side_effect=AssertionError('no protected/stale capture'))
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,'missing_evidence')
                self.assertTrue(flow.host_startup_complete);self.assertIsNone(flow.pending_host)
                flow.controller.type_ascii.assert_called_once_with(value)
                self.assertEqual(flow.controller.click.call_count,2)
                self.assertEqual(flow.actions,1);flow.native.capture_host.assert_not_called()
                self.assertEqual(flow.startup_index,len(F.HOST_STARTUP))

    def test_complete_reply_stream_and_exact_reviewer_path_use_balanced_bounded_batches(self):
        # Combine both authoritative synthetic fixture shapes without reading a token.
        reviewer=D.ReviewerArtifactTests();reviewer.setUp();self.addCleanup(reviewer.doCleanups)
        fixture=self.startup.fixture;root=self.startup.root
        fixture._data['delivery_choices']=reviewer.choices
        pathlib.Path(fixture._data['delivery_choices_file']).write_text(json.dumps(reviewer.choices))
        for index,source in enumerate(fixture._data['sources'],1):
            account=str(index)*64;entry={'account_id':account};path=root/f'coordinated-fixture-source-{index}-entry.json'
            path.write_text(json.dumps(entry));path.chmod(0o600)
            source.update(entry_selection=entry,entry_selection_file=str(path),reopen_selector={'account_id':account})
            source['original_capture']['scope'].update(account_id=account,participant_id=f'synthetic-participant-{index}')
            source['original_capture']['request']={'operation_id':f'private-original-native-capture-{index}'}
        # Both independently imported fixture modules use the same disposable base.
        with mock.patch.object(F.S.F,'ARTIFACT_PARENT',root.parent):
            flow=self.startup.flow();controller=B.RecordingController();flow.controller=controller
            flow.native.controller=controller
            stamp=dict(revision=1,nonws_end=1,context_valid=True,entry='Editing',editor=dict(ordinal=1,revision=1),view=None)
            flow.native.stable=lambda *a,**kw:{'host_input':True,'secret_input':False,'host_observation':stamp}
            flow.native.point=lambda *a:(100,100)
            expected=[]
            for index,prompt in enumerate(self.startup.PROMPTS):
                reply=flow.expected_host_line(prompt);self.assertFalse(flow.host_startup_complete)
                kind,value=reply
                if kind=='secret':
                    flow.native.protected_input('Selecting',None,'HostEditor',fixture.secret('host'),(0,1,1))
                    expected.extend(B.K._ascii_events(F.S.F._SYNTHETIC_PASSWORDS['host'].decode('ascii')))
                else:
                    controller.type_ascii(value);expected.extend(B.K._ascii_events(value))
                flow.pending_host=reply;flow.pending_startup=index;flow.startup_submitted();flow.pending_host=None
                self.assertFalse(flow.host_startup_complete)
                flow.pump_host(O.observed_snapshot(host_input=True,secret_input=False))
                self.assertFalse(flow.host_startup_complete)
                flow.pump_host(O.observed_snapshot(host_input=False,secret_input=False,widgets=[]))
            self.assertTrue(flow.host_startup_complete)
            kind,path=flow.expected_host_line('Exact coordinated reviewer selection JSON')
            self.assertEqual((kind,path),('public',str(root/'coordinated-reviewer-selection-1.json')))
            self.assertTrue(pathlib.Path(path).is_file());self.assertFalse(path.startswith('{'))
            controller.type_ascii(path);expected.extend(B.K._ascii_events(path))
            self.assertIsNone(flow.expected_host_line('Exact coordinated reviewer selection JSON'))
            self.assertEqual(flow.reviewer_index,1)
            self.assertEqual(tuple(event for batch in controller.batches for event in batch),tuple(expected))
            self.assertTrue(all(B.raw_event_count(batch)+3<=256 for batch in controller.batches))
            self.assertFalse(controller.held);self.assertFalse(controller.pending)
            self.assertFalse((root/'coordinated-host-runtime-session.token').exists())
            self.assertEqual(len(fixture.secret_instances),2)
            self.assertTrue(all(not any(secret._bytes) for secret in fixture.secret_instances))


class SemanticRuntimeCpuContractTests(unittest.TestCase):
    """Fabricated Docker records only; no Docker, native process or fixture."""
    def setUp(self):
        self.S=F.load('ci-financial-supervisor')

    def inspection(self,nano_cpus=4_000_000_000):
        S=self.S
        return [dict(Image='sha256:'+'a'*64,Mounts=[],Config=dict(
            Labels={S.LABEL:'token',S.SOURCE_LABEL:'b'*40},Image='sha256:'+'a'*64,
            User='0:0',Volumes=None,Entrypoint=['/usr/local/bin/python3','-I','-B','/opt/ci-financial/ci-financial-container.py'],
            Cmd=[]),HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,Privileged=False,
            CapDrop=['ALL'],CapAdd=['SETUID','SETGID'],SecurityOpt=['no-new-privileges:true'],
            PidsLimit=128,Memory=2*1024**3,MemorySwap=2*1024**3,NanoCpus=nano_cpus,
            Binds=None,Devices=[],DeviceRequests=None,Mounts=None,PidMode='',IpcMode='private',
            UsernsMode='',CgroupnsMode='private',GroupAdd=None,Tmpfs=dict(S.TMPFS),
            LogConfig={'Type':'none','Config':{}},RestartPolicy={'Name':'no','MaximumRetryCount':0},
            AutoRemove=False,Ulimits=[{'Name':'core','Soft':0,'Hard':0},
                                     {'Name':'nofile','Soft':512,'Hard':512}]))]

    def check_inspection(self,profile,rows,expected_failure=None):
        S=self.S;output=io.StringIO()
        with mock.patch.object(S.I,'profile',return_value=profile), \
             mock.patch.object(S,'docker',return_value=json.dumps(rows).encode()), \
             contextlib.redirect_stdout(output):
            if expected_failure is None:
                S.inspect_isolation('name','token','external','sha256:'+'a'*64,'b'*40)
                self.assertEqual(output.getvalue(),'')
                return
            with self.assertRaises(S.Failure) as caught:
                S.inspect_isolation('name','token','external','sha256:'+'a'*64,'b'*40)
        self.assertEqual(caught.exception.check,expected_failure)
        record=json.loads(output.getvalue().split(' ',1)[1])
        self.assertEqual(record['check'],expected_failure)
        self.assertTrue(record['cleanup_pending'])
        self.assertNotIn('PRIVATE_SENTINEL',output.getvalue())

    def test_semantic_four_and_legacy_two_are_exact_not_minimum_limits(self):
        S=self.S
        for profile,expected,wrong in ((S.P.C.SEMANTIC_PROFILE,4_000_000_000,2_000_000_000),
                                       (S.P.C.EXTERNAL_PROFILE,2_000_000_000,4_000_000_000)):
            with self.subTest(profile=profile):
                self.check_inspection(profile,self.inspection(expected))
            for value in (None,False,True,0,-1,wrong,3_000_000_000,2**50,float(expected),str(expected),'PRIVATE_SENTINEL'):
                with self.subTest(profile=profile,value=value):
                    self.check_inspection(profile,self.inspection(value),'cpu_limit')
            rows=self.inspection(expected);del rows[0]['HostConfig']['NanoCpus']
            self.check_inspection(profile,rows,'cpu_limit')

    def test_other_resource_caps_and_isolation_stay_fail_closed(self):
        S=self.S
        changes=(('PidsLimit',0,'pids_limit'),('PidsLimit',256,'pids_limit'),
            ('Memory',0,'memory_limit'),('Memory',4*1024**3,'memory_limit'),
            ('MemorySwap',-1,'swap_limit'),('MemorySwap',4*1024**3,'swap_limit'),
            ('NetworkMode','host','network'),('ReadonlyRootfs',False,'readonly_root'),
            ('Privileged',True,'privileged'),('CapDrop',[],'cap_drop'),
            ('CapAdd',['SETUID','SETGID','SYS_ADMIN'],'cap_add'),
            ('SecurityOpt',[],'no_new_privileges'),('PidMode','host','pid_namespace'),
            ('IpcMode','host','ipc_namespace'),('UsernsMode','host','user_namespace'),
            ('CgroupnsMode','host','cgroup_namespace'),('GroupAdd',[1],'supplementary_groups'),
            ('Binds',['PRIVATE_SENTINEL'],'bind_mounts'),('Devices',['PRIVATE_SENTINEL'],'devices'),
            ('DeviceRequests',['PRIVATE_SENTINEL'],'device_requests'),('Mounts',['PRIVATE_SENTINEL'],'extra_mounts'),
            ('LogConfig',{'Type':'json-file','Config':{}},'log_driver'),
            ('RestartPolicy',{'Name':'always','MaximumRetryCount':0},'restart_policy'),
            ('AutoRemove',True,'auto_remove'),('Ulimits',[],'ulimits'))
        for profile,cpus in ((S.P.C.SEMANTIC_PROFILE,4_000_000_000),(S.P.C.EXTERNAL_PROFILE,2_000_000_000)):
            for field,value,check in changes:
                with self.subTest(profile=profile,field=field,value=value):
                    rows=self.inspection(cpus);rows[0]['HostConfig'][field]=value
                    self.check_inspection(profile,rows,check)
            rows=self.inspection(cpus);rows[0]['HostConfig']['Tmpfs']['/tmp']+=',exec'
            self.check_inspection(profile,rows,'tmpfs_options')
            rows=self.inspection(cpus);rows[0]['Config']['User']='10001:10001'
            self.check_inspection(profile,rows,'setup_user')

    def test_creation_uses_profile_quota_and_preserves_all_other_arguments(self):
        S=self.S
        tmpfs={
            '/etc/wholepact':'rw,noexec,nosuid,nodev,size=64k,mode=0755',
            '/run/ci-account':'rw,noexec,nosuid,nodev,size=64k,mode=0755',
            '/ci-fixture':'rw,noexec,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=0700',
            '/run/ci-financial-wayland':'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700',
            '/ci-financial-evidence':'rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700',
            '/ci-financial-control':'rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700',
            '/tmp':'rw,noexec,nosuid,nodev,size=64m,mode=1777',
            '/dev/shm':'rw,noexec,nosuid,nodev,size=128m,mode=1777'}
        self.assertEqual(S.TMPFS,tmpfs)
        for profile,cpus in ((S.P.C.SEMANTIC_PROFILE,'4'),(S.P.C.EXTERNAL_PROFILE,'2')):
            candidate=dict(schema=1,profile=profile,native_oracle_verified=True,
                fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)
            def command(args,stage,**kwargs):
                kwargs['on_line'](b'CI_FINANCIAL_CANDIDATE '+json.dumps(candidate).encode())
                return 0,b''
            with self.subTest(profile=profile),mock.patch.object(S.I,'profile',return_value=profile), \
                 mock.patch.object(S,'names',return_value=[]),mock.patch.object(S,'docker') as docker, \
                 mock.patch.object(S,'inspect_isolation') as inspect, \
                 mock.patch.object(S,'docker_env',return_value={}), \
                 mock.patch.object(S,'remove_container') as remove, \
                 mock.patch.object(S,'command',side_effect=command) as start:
                result,passed=S.run_case('external','sha256:'+'a'*64,'token','b'*40)
            self.assertEqual(result,candidate);self.assertTrue(passed)
            name='wp-financial-token-external'
            expected=['create','--pull','never','--name',name,'--label',S.LABEL+'=token',
                '--label',S.SOURCE_LABEL+'='+'b'*40,'--network','none','--read-only','--cap-drop','ALL',
                '--cap-add','SETUID','--cap-add','SETGID','--security-opt','no-new-privileges:true',
                '--pids-limit','128','--memory','2g','--memory-swap','2g','--cpus',cpus,
                '--ipc','private','--cgroupns','private','--ulimit','core=0:0','--ulimit','nofile=512:512',
                '--log-driver','none','--restart','no']
            for path,options in tmpfs.items():expected+=['--tmpfs',path+':'+options]
            docker.assert_called_once_with(expected+['sha256:'+'a'*64],'container',limit=4096)
            inspect.assert_called_once_with(name,'token','external','sha256:'+'a'*64,'b'*40)
            remove.assert_called_once_with(name,'token')
            self.assertEqual(start.call_args.args,(['docker','start','--attach',name],'runtime'))
            self.assertEqual(start.call_args.kwargs['seconds'],1830)
            self.assertEqual(start.call_args.kwargs['limit'],16384)

    def test_unknown_profile_does_not_select_a_quota(self):
        with mock.patch.object(self.S.I,'profile',return_value='unreviewed-profile'):
            with self.assertRaises(self.S.Failure) as caught:self.S.runtime_cpu_limit()
        self.assertEqual(caught.exception.check,'artifact_profile')


if __name__=='__main__':unittest.main()
