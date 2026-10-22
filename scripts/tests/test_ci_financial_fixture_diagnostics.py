"""Pure closed-protocol regressions; no native product, credentials or container."""
import contextlib
import importlib.util
import io
import json
import pathlib
import os
import re
import socket
import stat
import tempfile
import sys
import unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_container_tested',ROOT/'ci-financial-container.py')
M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)

class FixtureDiagnostics(unittest.TestCase):
    def value(self):
        return dict(version=1,phase='child_stage',reason='ChildExit',next=12,expected=200,
                    process_cleanup=True,root_cleanup=True)
    def line(self,value):
        return M.DIAGNOSTIC+json.dumps(value,separators=(',',':')).encode()
    def test_real_pathname_socket_bind_in_container_shaped_private_tree(self):
        source=next((ROOT.parent/'crates/wholepact-native-host/src').rglob('coordinated_full_fixture_v1.rs')).read_text()
        prefix=re.search(r'const FULL_ROOT_PREFIX: &str = "([a-z-]+)";',source).group(1)
        with tempfile.TemporaryDirectory(prefix='wp-bind---',dir='/tmp') as base:
            self.assertEqual(len(base),len('/ci-fixture/full-parent'))
            for outer,binds in [('full-original-',False),(prefix,True)]:
                parent=pathlib.Path(base)/(outer+'aaaaaa')
                endpoint=parent/'wholepact-born-manual-ipc-bbbbbb'
                parent.mkdir(mode=0o700);endpoint.mkdir(mode=0o700)
                for directory in (pathlib.Path(base),parent,endpoint):
                    meta=directory.lstat()
                    self.assertTrue(stat.S_ISDIR(meta.st_mode))
                    self.assertEqual(stat.S_IMODE(meta.st_mode),0o700)
                    self.assertEqual(meta.st_uid,os.geteuid())
                path=str(endpoint/('requests-'+'00'*12+'.sock'))
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                    if binds:
                        self.assertEqual(len(path),104)
                        listener.bind(path)
                        self.assertEqual(listener.getsockname(),path)
                        self.assertTrue(stat.S_ISSOCK(os.lstat(path).st_mode))
                        self.assertEqual(os.lstat(path).st_uid,os.geteuid())
                    else:
                        self.assertEqual(len(path),116)
                        with self.assertRaises(OSError):listener.bind(path)

    def test_closed_rust_reason_enum_and_emission_phases_match_parser(self):
        source=next((ROOT.parent/'crates/wholepact-native-host/src').rglob('sequential_construction_v3_qualification.rs')).read_text()
        enum=re.search(r'enum HarnessFailureReason \{([^}]+)\}',source).group(1)
        reasons=set(re.findall(r'([A-Za-z0-9]+),',enum))
        self.assertEqual(reasons|{'Setup'},set(M.FIXTURE_REASONS))
        source=next((ROOT.parent/'crates/wholepact-native-host/src').rglob('coordinated_full_fixture_v1.rs')).read_text()
        phases=set(re.findall(r'phase = "([a-z_]+)"',source))
        self.assertEqual(phases|{'child_identity','child_directory','child_exec'},set(M.FIXTURE_PHASES))

    def test_every_closed_phase_and_reason(self):
        for phase in M.FIXTURE_PHASES:
            for reason in M.FIXTURE_REASONS:
                value=self.value()|dict(phase=phase,reason=reason)
                self.assertEqual(M.fixture_diagnostic(self.line(value)),value)
    def test_reject_unknown_private_text_wrong_types_and_counter_overflow(self):
        for field,values in dict(version=[True,2,'1'],phase=['private-source',[],None],
            reason=['password=private',[],None],next=[True,-1,201,1.5],expected=[True,-1,4097],
            process_cleanup=[1,'true',None],root_cleanup=[0,'false',None]).items():
            for replacement in values:
                value=self.value()|{field:replacement}
                with self.subTest(field=field,value=replacement), self.assertRaises(Exception):
                    M.fixture_diagnostic(self.line(value))
        for value in (self.value()|{'transcript':'private'}, {k:v for k,v in self.value().items() if k!='reason'}):
            with self.assertRaises(Exception):M.fixture_diagnostic(self.line(value))
    def test_no_raw_line_or_error_is_forwarded(self):
        parent=M.FixtureParent.__new__(M.FixtureParent)
        parent.deadline=100;parent.pending=bytearray();parent.total=0;parent.diagnostic=None
        parent.process=mock.Mock();parent.process.stdout.fileno.return_value=42
        selector=mock.MagicMock();selector.__enter__.return_value=selector;selector.select.return_value=[True]
        line=self.line(self.value())
        blocks=[b'private-child-output\n'+line[:15],line[15:]+b'\nprivate-trailer\n']
        out=io.StringIO()
        with mock.patch.object(M.selectors,'DefaultSelector',return_value=selector), \
             mock.patch.object(M.time,'monotonic_ns',return_value=0), \
             mock.patch.object(M.os,'read',side_effect=blocks),contextlib.redirect_stdout(out):
            with self.assertRaises(Exception):parent.wait_marker(M.READY)
        self.assertEqual(out.getvalue().strip(),line.decode())
        self.assertNotIn('private-child-output',out.getvalue())
        self.assertNotIn('private-trailer',out.getvalue())
    def test_malformed_diagnostic_emits_nothing(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out),self.assertRaises(Exception):
            M.emit_fixture_diagnostic(M.fixture_diagnostic(self.line(self.value()|{'reason':'secret'})))
        self.assertEqual(out.getvalue(),'')

if __name__=='__main__':unittest.main()
