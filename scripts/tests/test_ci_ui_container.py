"""Pure passwd/source invariants; never runs the container/setup entrypoint."""
import ast
import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).parents[1] / 'ci-ui-container.py'
SPEC = importlib.util.spec_from_file_location('ci_ui_container', PATH)
C = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(C)
BASE = b'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'


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
        body = source[source.index('def prepare_runtime('):source.index('def disabled_main(')]
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

    def test_disabled_main_never_calls_runtime_or_subprocess(self):
        tree = ast.parse(PATH.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'disabled_main')
        calls = [n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        self.assertNotIn('prepare_runtime', calls)
        self.assertNotIn('root_context', calls)
        self.assertIn("'integration_not_frozen'", ast.get_source_segment(PATH.read_text(), node))


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
        self.assertLess(body.index('P.project_case('), body.index('session.end_display()'))
        self.assertLess(body.index('session.end_display()'), body.index('session.collector.erase_after_case()'))
        self.assertNotIn('.kill(', body)

    def test_only_positive_case_launches_same_stream_after_native_arm(self):
        source = PATH.read_text(); body = source[source.index('def source_case('):source.index('def smoke_case(')]
        self.assertEqual(body.count('LibSelector(OWNER_SELECTOR'), 1)
        self.assertLess(body.index("r['detail']['direction'] == 'Native'"), body.index('LibSelector(OWNER_SELECTOR'))
        self.assertIn("if case == 'cancel':", body); self.assertIn("elif case == 'blur':", body)
        self.assertNotIn('close_window()', body)

    def test_one_retained_fixture_and_same_artifact_across_cases(self):
        source = PATH.read_text(); body = source[source.index('def reviewed_runtime_main('):source.index('def disabled_main(')]
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
