"""Pure passwd/source invariants; never runs the container/setup entrypoint."""
import ast
import importlib.util
import pathlib
import unittest
from types import SimpleNamespace

PATH = pathlib.Path(__file__).parents[1] / 'ci-ui-container.py'
SPEC = importlib.util.spec_from_file_location('ci_ui_container', PATH)
C = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(C)
BASE = b'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'


class ImageOwnership(unittest.TestCase):
    def meta(self, name, **changes):
        owner = 10001 if name == 'pristine-setup' else 0
        values = dict(st_uid=owner, st_gid=owner, st_nlink=1, st_size=12,
                      st_mode=C.stat.S_IFREG | (0o555 if name in C.ARTIFACTS else 0o444))
        return SimpleNamespace(**(values | changes))

    def test_only_synthetic_setup_image_uses_fixture_uid(self):
        for name in C.FILES:
            C.require_image_file_identity(name, self.meta(name), {'size':12})
        for name in ('coordinator-production', 'coordinator-observed', 'ci-ui-container.py'):
            with self.assertRaises(C.S.Rejected):
                C.require_image_file_identity(name, self.meta(name, st_uid=10001, st_gid=10001), {'size':12})
        with self.assertRaises(C.S.Rejected):
            C.require_image_file_identity('pristine-setup', self.meta('pristine-setup', st_uid=0, st_gid=0), {'size':12})

    def test_setup_identity_still_refuses_links_writes_size_or_gid_changes(self):
        for changes in ({'st_gid':0}, {'st_nlink':2}, {'st_size':13},
                        {'st_mode':C.stat.S_IFLNK|0o555}, {'st_mode':C.stat.S_IFREG|0o755}):
            with self.assertRaises(C.S.Rejected):
                C.require_image_file_identity('pristine-setup', self.meta('pristine-setup', **changes), {'size':12})

    def test_readonly_container_and_no_image_bind_mount_are_preserved(self):
        source = (PATH.parent / 'ci-ui-supervisor.py').read_text()
        self.assertIn("'--read-only'", source)
        self.assertIn("host.get('ReadonlyRootfs') is True", source)
        self.assertIn("mount.get('Type') == 'tmpfs'", source)
        self.assertNotIn("'/opt/ci-ui':", source)
        container = PATH.read_text()
        self.assertIn("for directory in (pathlib.Path('/'), pathlib.Path('/opt'), ROOT)", container)
        self.assertIn('root_directory(directory', container)
        self.assertIn('os.statvfs(ROOT).f_flag & os.ST_RDONLY', container)


class DisplayFailureObservation(unittest.TestCase):
    def test_confirmed_exit_preserves_display_failure_and_queued_error(self):
        from unittest import mock
        import contextlib, io
        session = C.NativeSession.__new__(C.NativeSession)
        session.weston = mock.Mock()
        session.weston.poll.return_value = 1
        session.controller = mock.Mock()
        observation = dict(exit_status=1, packet='error', module_error='input')
        session.controller.observe_exited_compositor.return_value = observation
        session.reporter = C.FirstRuntimeFailure('fixture')
        session.reporter.case = 'cancel'; session.reporter.stage = 'prepare'
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(C.S.Rejected) as found: session.require_display_live()
            session.reporter.error(found.exception)
        self.assertEqual(found.exception.code, 'display_status')
        self.assertEqual(session.reporter.value['code'], 'display_status')
        self.assertEqual(session.reporter.value['display_observation'], observation)
        session.controller.observe_exited_compositor.assert_called_once_with(session.weston)

    def test_exit_observes_product_and_closed_delivery_failure(self):
        from unittest import mock
        import contextlib, io
        session = C.NativeSession.__new__(C.NativeSession)
        session.weston = mock.Mock(); session.weston.poll.return_value = 1
        session.product = mock.Mock(); session.product.poll.return_value = -11
        session.controller = mock.Mock()
        session.controller.observe_exited_compositor.return_value = dict(
            exit_status=1, packet='error', module_error='target', target_reason='destroyed')
        session.collector = mock.Mock(); session.collector.read.return_value = []
        session.reporter = C.FirstRuntimeFailure('fixture'); session.reporter.stage = 'prepare'
        with mock.patch.object(C.P, 'delivery_first_failure', return_value=dict(stage='InputValidation', cls='InvalidBinding', **{'class':'InvalidBinding'})), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(C.S.Rejected): session.require_display_live()
        value = session.reporter.value
        self.assertEqual(value['code'], 'display_status')
        self.assertEqual(value['display_observation']['product_exit_status'], -11)
        self.assertEqual(value['display_observation']['target_reason'], 'destroyed')
        self.assertEqual(value['delivery_class'], 'InvalidBinding')

    def test_both_exit_order_paths_read_collector_and_preserve_primary(self):
        from unittest import mock
        import contextlib, io
        for display_status, product_status, primary in ((None, -11, 'product_status'), (1, -11, 'display_status')):
            with self.subTest(primary=primary):
                session = C.NativeSession.__new__(C.NativeSession)
                session.original = session.deadline = C.time.monotonic_ns() + 10**9
                session.weston = mock.Mock(); session.weston.poll.return_value = display_status
                session.product = mock.Mock(); session.product.poll.return_value = product_status
                session.controller = mock.Mock()
                session.controller.observe_exited_compositor.return_value = dict(exit_status=1, packet='error', module_error='target', target_reason='destroyed')
                session.collector = mock.Mock(); session.collector.read.return_value = []
                session.reporter = C.FirstRuntimeFailure('fixture'); session.reporter.stage = 'prepare'; session.reporter.case = 'cancel'
                session.owner = None
                with mock.patch.object(C.P, 'delivery_first_failure', return_value={'stage':'InputValidation', 'class':'InvalidBinding'}), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(C.S.Rejected) as failure: session.check()
                    session.reporter.error(failure.exception)
                self.assertEqual(failure.exception.code, primary)
                self.assertEqual(session.reporter.value['code'], primary)
                self.assertEqual(session.reporter.value['delivery_class'], 'InvalidBinding')
                session.collector.read.assert_called_once()
                if primary == 'product_status':
                    self.assertEqual(session.reporter.value['product_observation'], {'exit_status':-11})
                    session.controller.observe_exited_compositor.assert_not_called()
                else:
                    self.assertEqual(session.reporter.value['display_observation']['product_exit_status'], -11)

    def test_product_failure_survives_unavailable_collector(self):
        from unittest import mock
        import contextlib, io
        session = C.NativeSession.__new__(C.NativeSession)
        session.product = mock.Mock(); session.product.poll.return_value = 101
        session.collector = mock.Mock(); session.collector.read.side_effect = ValueError('private text')
        session.reporter = C.FirstRuntimeFailure('fixture'); session.reporter.stage = 'prepare'
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(C.S.Rejected): session.require_product_live()
        self.assertEqual(session.reporter.value['product_observation'], {'exit_status':101})
        self.assertIsNone(session.reporter.value['delivery_class'])
        self.assertNotIn('private text', output.getvalue())

    def test_product_observation_rejects_unbounded_or_cross_class_data(self):
        for value in ({'exit_status':True}, {'exit_status':-65}, {'exit_status':256},
                      {'exit_status':1,'text':'private'}):
            with self.assertRaises(C.P.Rejected):
                C.P.failure('fixture', 'prepare', 'product_status', product_observation=value)
        with self.assertRaises(C.P.Rejected):
            C.P.failure('fixture', 'prepare', 'display_status', product_observation={'exit_status':1})

    def test_live_display_never_consumes_controller(self):
        from unittest import mock
        session = C.NativeSession.__new__(C.NativeSession)
        session.weston = mock.Mock(); session.weston.poll.return_value = None
        session.controller = mock.Mock()
        session.require_display_live()
        session.controller.observe_exited_compositor.assert_not_called()

    def test_display_observation_schema_is_closed(self):
        good = dict(exit_status=-11, packet='eof', module_error=None)
        C.P.failure('fixture', 'prepare', 'display_status', 'cancel', display_observation=good)
        for change in ({'exit_status':True}, {'exit_status':-65}, {'packet':'private'},
                       {'module_error':'private'}, {'extra':'private'}):
            with self.assertRaises(C.P.Rejected):
                C.P.failure('fixture', 'prepare', 'display_status', 'cancel', display_observation=good|change)
        with self.assertRaises(C.P.Rejected):
            C.P.failure('fixture', 'prepare', 'internal', 'cancel', display_observation=good)


class CommonFailureContext(unittest.TestCase):
    def context(self):
        return dict(product_status=1, compositor_status=None, field='Request', action='type',
            collector_code=None, record_count=0, phase=None, terminal_roles=[], delivery_stage=None, delivery_class=None,
            controller=dict(origin='product_exit', module_error='target', target_reason='unmapped',
                sequence=12, operation=5, commit=3, frame=4, input_sequence=11))

    def test_actual_context_reads_one_bounded_snapshot_without_commands(self):
        from unittest import mock
        session=C.NativeSession.__new__(C.NativeSession)
        session.records=[]; session.collector=mock.Mock(); session.collector.read.return_value=[]
        session.product=mock.Mock(); session.product.poll.return_value=-9
        session.weston=mock.Mock(); session.weston.poll.return_value=None
        session.controller=mock.Mock(); session.controller.failure_snapshot.return_value=self.context()['controller']
        session.input_field='Request'; session.input_action='type'
        context=session.failure_context()
        value=C.P.failure('fixture','input','display_binding')|{'runtime_observation':context}
        C.P.validate_failure(value,'fixture')
        self.assertEqual(context['product_status'],-9)
        session.collector.read.assert_called_once_with()
        session.controller.failure_snapshot.assert_called_once_with()
        self.assertEqual(len(session.controller.mock_calls),1)

    def test_every_primary_failure_gets_same_closed_context(self):
        from unittest import mock
        import contextlib, io
        for code in ('display_binding', 'display_status', 'product_status', 'input_phase'):
            first = C.FirstRuntimeFailure('fixture'); first.stage='input'; first.case='cancel'
            first.runtime_context = mock.Mock(return_value=self.context())
            with contextlib.redirect_stdout(io.StringIO()): first.note(C.P.failure('fixture','input',code,'cancel'))
            self.assertEqual(first.value['code'],code)
            self.assertEqual(first.value['runtime_observation'],self.context())
            first.runtime_context.assert_called_once()

    def test_hook_failure_and_reentrancy_cannot_replace_primary(self):
        import contextlib, io
        for behavior in ('raise','reenter'):
            first = C.FirstRuntimeFailure('fixture')
            def hook():
                if behavior == 'raise': raise ValueError('private payload')
                first.note(C.P.failure('fixture','input','internal'))
                return self.context()
            first.runtime_context=hook
            with contextlib.redirect_stdout(io.StringIO()) as output:
                first.note(C.P.failure('fixture','input','display_binding'))
                first.note(C.P.failure('fixture','input','internal'))
            self.assertEqual(first.value['code'],'display_binding')
            self.assertEqual(output.getvalue().count('CI_UI_FAILURE'),1)
            self.assertNotIn('private payload',output.getvalue())

    def test_arbitrary_callback_data_is_not_public(self):
        import contextlib, io
        for bad in (self.context()|{'field':'private/path'}, self.context()|{'secret':'private'},
                    self.context()|{'product_status':True}, self.context()|{'record_count':999999}):
            first=C.FirstRuntimeFailure('fixture'); first.runtime_context=lambda:bad
            with contextlib.redirect_stdout(io.StringIO()) as output:
                first.note(C.P.failure('fixture','input','display_binding'))
            self.assertNotIn('runtime_observation',first.value)
            self.assertNotIn('private',output.getvalue())


class RootSetup(unittest.TestCase):
    def test_exact_unrelated_passwd_preservation(self):
        result = C.passwd_bytes(BASE, '/ci-fixture/ui-original/home')
        self.assertTrue(result.startswith(BASE))
        self.assertEqual(result[len(BASE):], b'wholepact-ci:x:10001:10001:Disposable CI fixture:/ci-fixture/ui-original/home:/usr/sbin/nologin\n')

    def test_conflicting_name_or_uid_refused(self):
        for row in (b'wholepact-ci:x:42:42::/x:/bin/false\n', b'another:x:10001:42::/x:/bin/false\n'):
            with self.assertRaises(C.S.Rejected): C.passwd_bytes(BASE + row, '/nonexistent')

    def test_duplicate_base_names_refused(self):
        with self.assertRaises(C.S.Rejected): C.passwd_bytes(BASE + b'root:x:1:1::/x:/bin/sh\n', '/nonexistent')

    def test_passwd_injection_and_noncanonical_paths_refused(self):
        for home in ('relative', '/x:0:0', '/x\nroot', '/x\0', '/x/../y', '//x', '/x//y'):
            with self.assertRaises(C.S.Rejected): C.passwd_bytes(BASE, home)

    def test_base_must_be_bounded_ascii_complete_lines(self):
        for base in (b'', BASE[:-1], b'\xff\n', b'a' * 65537):
            with self.assertRaises(C.S.Rejected): C.passwd_bytes(base, '/nonexistent')

    def test_passcred_precedes_wrapper_spawn(self):
        source = PATH.read_text()
        body = source[source.index('def setup_one_fixture('):source.index('def base_passwd(')]
        self.assertLess(body.index('left.setsockopt'), body.index('subprocess.Popen'))
        self.assertIn('pass_fds=(right.fileno(),)', body)
        self.assertIn('extra_groups=[]', body)
        self.assertIn('env={}, close_fds=True', body)

    def test_live_wrapper_and_original_cutoff_before_ack(self):
        source = PATH.read_text()
        body = source[source.index('S.validate_received(value, fds, original)'):]
        self.assertLess(body.index('time.monotonic_ns() < original'), body.index("left.send(b'ACK1')"))
        self.assertLess(body.index('process.poll() is None'), body.index("left.send(b'ACK1')"))
        self.assertLess(body.index('process.wait('), body.index('S.namespace_empty_except((1,))'))

    def test_pin_and_empty_namespace_precede_permanent_drop(self):
        source = PATH.read_text()
        body = source[source.index('def prepare_runtime('):source.index('def invalid_invocation(')]
        self.assertEqual(body.count('create_pin('), 1)
        self.assertLess(body.index('setup_one_fixture'), body.index('create_pin('))
        self.assertLess(body.index('S.namespace_empty_except((1,))'), body.index('os.setgroups([])'))
        self.assertLess(body.index('os.setresuid'), body.index('S.identity()'))

    def test_root_does_not_read_full_private_handoff(self):
        source = PATH.read_text()
        privileged = source[:source.index('# New integrated source revision.')]
        self.assertNotIn('handoff.json', privileged)
        self.assertNotIn('private_handoff(', privileged)
        runtime = source[source.index('def reviewed_runtime_main('):]
        self.assertLess(runtime.index('prepare_runtime('), runtime.index('S.private_handoff('))

    def test_invalid_invocation_never_calls_runtime_or_subprocess(self):
        tree = ast.parse(PATH.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'invalid_invocation')
        calls = [n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        self.assertNotIn('prepare_runtime', calls)
        self.assertNotIn('root_context', calls)
        self.assertIn("'invalid_record'", ast.get_source_segment(PATH.read_text(), node))


if __name__ == '__main__': unittest.main()

# Fabricated bytes and mocked process/transport only. Never invoke a product,
# setup selector, socket, compositor, namespace opener, or container runtime.
import contextlib
import hashlib
import io
import json
import os
import tempfile
from unittest.mock import patch, Mock


class RuntimePure(unittest.TestCase):
    def original(self):
        request = '{"account_id":"' + 'a'*64 + '","operation_id":"original-test","expected_head":{"sequence":4,"digest":"' + 'b'*64 + '"}}'
        raw = json.dumps(dict(original_monotonic_cutoff_ns=123,
            fixture=dict(form=dict(request_json=request, owner_certificate_der_hex='0102', expected_account_id='a'*64)))).encode()
        return raw, request

    def test_exact_retained_request_bytes_not_python_serialization(self):
        raw, request = self.original(); _, facts = C.original_facts(raw, 123)
        expected = hashlib.sha256(b'wholepact:durable-delivery-admission-preparation:v3\0' + request.encode()).hexdigest()
        self.assertEqual(facts['request_commitment'], expected)
        self.assertEqual(facts['descriptor_digest'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(facts['owner_certificate_digest'], hashlib.sha256(b'\x01\x02').hexdigest())
        normalized = json.dumps(json.loads(request), sort_keys=True).encode()
        self.assertNotEqual(request.encode(), normalized)
        self.assertNotEqual(expected, hashlib.sha256(b'wholepact:durable-delivery-admission-preparation:v3\0' + normalized).hexdigest())

    def test_original_cutoff_mismatch_is_not_refreshed(self):
        raw, _ = self.original()
        with self.assertRaises(C.S.Rejected) as caught: C.original_facts(raw, 124)
        self.assertEqual(caught.exception.code, 'original_deadline')

    def test_request_domain_and_exporter_bytes_have_source_provenance(self):
        root = PATH.parents[1]
        lib = (root/'crates/wholepact-authority/src/lib.rs').read_text()
        transport = (root/'crates/wholepact-authority/src/transport.rs').read_text()
        preparation = (root/'crates/wholepact-authority/src/transport/durable_delivery_admission_v3.rs').read_text()
        exporter = (root/'crates/wholepact-authority/src/native_witness_owner/window/ephemeral_fixture_v1/durable_delivery_admission_v2.rs').read_text()
        self.assertIn('serde_json::to_vec(v)', lib)
        self.assertIn('h.update(domain.as_bytes());\n    h.update([0]);\n    h.update(&*b);', lib)
        self.assertIn('digest("wholepact:durable-delivery-admission-preparation:v3",request)', preparation)
        self.assertIn('serde_json::to_string(request)', exporter)
        self.assertIn('hex::encode(Sha256::digest(certificate.as_ref()))', transport)

    def test_actual_rect_scaled_floor_ceil_only(self):
        snapshot = dict(pixels_per_point=1.5)
        widget = dict(rect=dict(left=1.2, top=2.3, right=4.5, bottom=6.7))
        self.assertEqual(C.physical_region(snapshot, widget), dict(left=1, top=3, right=7, bottom=11))
        widget['rect']['left'] = -1
        with self.assertRaises(C.S.Rejected): C.physical_region(snapshot, widget)

    def test_pixel_hash_uses_only_actual_region(self):
        pixels = bytearray(C.D.FRAME_BYTES); region = dict(left=1, top=1, right=2, bottom=2)
        before = C.pixel_digest(pixels, region)
        pixels[0] = 255; self.assertEqual(before, C.pixel_digest(pixels, region))
        pixels[(C.D.WIDTH + 1)*4] = 255
        self.assertNotEqual(before, C.pixel_digest(pixels, region))
        with self.assertRaises(C.S.Rejected): C.pixel_digest(b'not-a-frame', region)

    def test_first_error_emitted_once_and_survives_cleanup(self):
        first = C.FirstRuntimeFailure('fixture'); first.case = 'cancel'; first.stage = 'prepare'
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            first.error(C.S.Rejected('source_prepare'))
            first.error(C.S.Rejected('cleanup_failed'))
        self.assertEqual(out.getvalue().count('CI_UI_FAILURE '), 1)
        self.assertEqual(first.value['code'], 'source_prepare')
        self.assertEqual(first.value['case'], 'cancel')
        self.assertNotIn('cleanup_failed', out.getvalue())

    def helper(self, owner=False):
        helper = C.LibSelector.__new__(C.LibSelector)
        helper.selector = C.OWNER_SELECTOR if owner else C.S.SELECTOR_PREFIX + 'coordinator_pristine_originals_after_cancel_or_blur'
        helper.owner, helper.result, helper.failure_seen = owner, None, False
        helper.counts = {'running':0, 'result':0, 'marker':0}
        helper.reporter = C.FirstRuntimeFailure('fixture'); helper.reporter.case = 'append' if owner else 'cancel'
        return helper

    def test_real_lib_result_requires_exact_nonzero_count(self):
        helper = self.helper()
        helper.line(b'running 1 test')
        helper.line(b'CI_UI_FIXTURE_AUDIT {"version":1}')
        helper.line(b'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s')
        self.assertEqual(helper.counts, {'running':1,'result':1,'marker':1})
        for line in (b'running 1 test', b'CI_UI_FIXTURE_AUDIT {"version":1}',
                     b'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s'):
            with self.assertRaises(C.S.Rejected): helper.line(line)

    def test_client_actual_nested_first_cause_is_retained(self):
        helper = self.helper(True); out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(C.S.Rejected):
            helper.line(b'CI_UI_OWNER_CLIENT_FAILURE stage=BeforeSendSource cause=Source(Storage)')
        self.assertEqual(helper.reporter.value['code'], 'owner_client_BeforeSendSource_Source_Storage')
        self.assertNotIn('Source(Storage)', out.getvalue())
        with self.assertRaises(C.S.Rejected): helper.line(b'CI_UI_OWNER_CLIENT_FAILURE stage=Prepare cause=NotListening')
        self.assertEqual(helper.reporter.value['code'], 'owner_client_BeforeSendSource_Source_Storage')

    def test_unknown_private_helper_marker_cannot_be_ignored(self):
        with self.assertRaises(C.S.Rejected): self.helper().line(b'CI_UI_UNEXPECTED private-data')

    def test_expired_original_failure_never_runs_native(self):
        out = io.StringIO()
        with patch.object(C, 'prepare_runtime', side_effect=C.S.Rejected('original_deadline')) as setup, \
             patch.object(C, 'NativeSession') as native, contextlib.redirect_stdout(out):
            self.assertEqual(C.reviewed_runtime_main('fixture'), 1)
        native.assert_not_called(); setup.assert_called_once()
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        final = json.loads(lines[-1]); self.assertFalse(final['natural_empty'])
        self.assertEqual(final['first_failure']['code'], 'original_deadline')

    def test_teardown_compositor_refuses_live_product(self):
        session = C.NativeSession.__new__(C.NativeSession)
        session.product = Mock(returncode=None); session.weston = Mock(); session.controller = Mock()
        with self.assertRaises(C.S.Rejected): session.end_display()
        session.weston.terminate.assert_not_called(); session.controller.close.assert_not_called()

    def test_product_environment_is_only_original_wayland_pair(self):
        source = PATH.read_text()
        self.assertIn("environment = {'XDG_RUNTIME_DIR': str(WAYLAND), 'WAYLAND_DISPLAY': 'wayland-ui'}", source)
        body = source[source.index('class NativeSession:'):source.index('    def check(self):', source.index('class NativeSession:'))]
        self.assertIn('close_fds=True, pass_fds=(), env=environment', body)
        self.assertNotIn('LIBGL_ALWAYS_SOFTWARE', body); self.assertNotIn('EGL_PLATFORM', body)

    def test_source_custody_audit_follows_whole_product_drain(self):
        source = PATH.read_text(); body = source[source.index('def source_case('):source.index('def smoke_case(')]
        self.assertLess(body.index('drain = session.drain_product()'), body.index('audit = LibSelector('))
        self.assertLess(body.index('session.end_display()'), body.index('audit = LibSelector('))
        self.assertLess(body.index('session.end_display()'), body.index('session.collector.erase_after_case()'))
        self.assertNotIn('.kill(', body)

    def test_only_positive_case_launches_same_stream_after_native_arm(self):
        source = PATH.read_text(); body = source[source.index('def source_case('):source.index('def smoke_case(')]
        self.assertEqual(body.count('LibSelector(OWNER_SELECTOR'), 1)
        self.assertLess(body.index("r['detail']['direction'] == 'Native'"), body.index('LibSelector(OWNER_SELECTOR'))
        self.assertIn("if case == 'cancel':", body); self.assertIn("elif case == 'blur':", body)
        self.assertNotIn('close_window()', body)

    def test_one_retained_fixture_and_same_artifact_across_cases(self):
        source = PATH.read_text(); body = source[source.index('def reviewed_runtime_main('):source.index('def invalid_invocation(')]
        self.assertEqual(body.count('prepare_runtime('), 1)
        self.assertEqual(body.count('S.private_handoff('), 1)
        self.assertIn('for case in P.CASES:', body)
        self.assertIn('source_case(case, original, raw, retained, digest, reporter)', body)
        self.assertNotIn('create_pin(', body)

    def test_live_collector_partial_suffix_waits_final_refuses(self):
        record = dict(version=1, sequence=1, role='Coordinator', pid=100, ppid=1, original_parent_pid=1,
            elapsed_ms=1, event='RetainedBindings', detail=dict(children=[dict(role=r, pid=200+i)
            for i,r in enumerate(sorted(C.P._OBSERVER_CHILDREN['Coordinator']))],
            startup_deadline_ms=30000, session_deadline_ms=300000))
        raw = json.dumps(record).encode() + b'\n'
        with tempfile.TemporaryDirectory() as root, patch.object(C, 'EVIDENCE', pathlib.Path(root)), patch.object(C.S, 'UID', os.getuid()):
            path = pathlib.Path(root)/'100.jsonl'
            fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd,'wb') as out: out.write(raw + b'{"incomplete":')
            collector = C.ObserverFiles()
            self.assertEqual(len(collector.read()), 1)
            with self.assertRaises(C.S.Rejected): collector.read(final=True)
            path.write_bytes(raw.replace(b'Coordinator', b'CoordinatoX'))
            with self.assertRaises(C.S.Rejected) as caught: collector.read()
            self.assertEqual(caught.exception.code, 'record_sequence')

    def test_original_selector_is_actual_module_namespace(self):
        self.assertIn('sequential_construction_v3::qualification::', C.OWNER_SELECTOR)
        self.assertNotIn('sequential_construction_v3_qualification::', C.OWNER_SELECTOR)
        self.assertTrue(C.OWNER_SELECTOR.endswith('pristine_owner_client_v1::coordinator_pristine_owner_same_stream_one_append'))


class TerminalHelperPure(unittest.TestCase):
    helper = RuntimePure.helper
    def test_owner_eof_failure_is_immediate_without_waiting_ui_phase(self):
        helper = self.helper(True); helper.original = 200
        helper.pending = bytearray(); helper.poller = Mock()
        helper.poller.select.return_value = []; helper.poller.get_map.return_value = {}
        helper.process = Mock(); helper.process.poll.return_value = 101
        with patch.object(C.time, 'monotonic_ns', return_value=100), self.assertRaises(C.S.Rejected) as caught:
            helper.pump()
        self.assertEqual(caught.exception.code, 'owner_response')

    def test_typed_failure_cr_is_not_normalized(self):
        with self.assertRaises(C.P.Rejected):
            self.helper(True).line(b'CI_UI_OWNER_CLIENT_FAILURE stage=Prepare cause=NotListening\r')
