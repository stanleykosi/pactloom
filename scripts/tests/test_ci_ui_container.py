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
        self.assertNotIn('handoff.json', source)
        self.assertNotIn('private_handoff(', source)

    def test_disabled_main_never_calls_runtime_or_subprocess(self):
        tree = ast.parse(PATH.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'disabled_main')
        calls = [n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        self.assertNotIn('prepare_runtime', calls)
        self.assertNotIn('root_context', calls)
        self.assertIn("'integration_not_frozen'", ast.get_source_segment(PATH.read_text(), node))


if __name__ == '__main__': unittest.main()
