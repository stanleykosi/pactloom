"""Pure mocked custody/parser tests, never native setup, sockets or subprocesses."""
import array
import importlib.util
import json
import os
import pathlib
import re
import socket
import stat
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('ci_ui_setup', pathlib.Path(__file__).parents[1] / 'ci-ui-setup-wrapper.py')
S = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(S)


def custody():
    return dict(version=1, kind='custody', root_path='/ci-fixture/ui-original',
        home_path='/ci-fixture/ui-original/home', root_device=3, root_inode=10,
        home_device=3, home_inode=11, original_monotonic_cutoff_ns=900_000_000_001)


def ancillary(pid=42, fds=(50, 51)):
    return [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('3i', pid, 10001, 10001)),
        (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds).tobytes())]


class Custody(unittest.TestCase):
    def receive(self, controls=None, data=None, flags=0):
        edge = Mock(); edge.recvmsg.return_value = (
            json.dumps(custody()).encode() if data is None else data,
            ancillary() if controls is None else controls, flags, None)
        wrapper = Mock(pid=42); wrapper.poll.return_value = None
        with patch.object(S.os, 'close') as close, patch.object(S, 'validate_received', return_value=custody()):
            try:
                value = S.receive_custody(edge, wrapper, custody()['original_monotonic_cutoff_ns'])
                return value, close.call_args_list
            except S.Rejected as error:
                return error.code, close.call_args_list

    def test_success_transfers_exact_two_fds_to_caller(self):
        result, closed = self.receive()
        self.assertEqual(result, (custody(), [50, 51])); self.assertEqual(closed, [])

    def test_truncation_closes_all_installed_rights(self):
        for flag in (socket.MSG_CTRUNC, socket.MSG_TRUNC):
            result, closed = self.receive(flags=flag)
            self.assertEqual(result, 'custody_packet')
            self.assertEqual([c.args[0] for c in closed], [50, 51])

    def test_unknown_control_closes_rights(self):
        result, closed = self.receive(ancillary() + [(socket.SOL_SOCKET, 999, b'private')])
        self.assertEqual(result, 'custody_packet'); self.assertEqual(len(closed), 2)

    def test_wrong_live_sender_closes_rights(self):
        result, closed = self.receive(ancillary(pid=43))
        self.assertEqual(result, 'custody_credentials'); self.assertEqual(len(closed), 2)

    def test_duplicate_credentials_refused(self):
        controls = ancillary(); controls.append(controls[0])
        result, closed = self.receive(controls)
        self.assertEqual(result, 'custody_credentials'); self.assertEqual(len(closed), 2)

    def test_duplicate_rights_control_refused_and_all_closed(self):
        controls = ancillary(); controls.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [52]).tobytes()))
        result, closed = self.receive(controls)
        self.assertEqual(result, 'custody_rights'); self.assertEqual([c.args[0] for c in closed], [50, 51, 52])

    def test_malformed_json_keeps_rights_cleanup(self):
        result, closed = self.receive(data=b'{"kind":"custody","kind":"error"}')
        self.assertEqual(result, 'duplicate_key'); self.assertEqual(len(closed), 2)

    def test_malformed_right_bytes_still_close_complete_installed_fds(self):
        controls = ancillary(); controls[1] = (*controls[1][:2], controls[1][2] + b'x')
        result, closed = self.receive(controls)
        self.assertEqual(result, 'custody_packet'); self.assertEqual(len(closed), 2)

    def test_error_packet_has_no_rights(self):
        data = json.dumps(dict(version=1, kind='error', stage='setup', code='setup_source',
            source_boundary='BirthEnroll', source_outcome='AuthorityAuthentication')).encode()
        result, closed = self.receive(ancillary()[:1], data)
        self.assertEqual(result[0]['code'], 'setup_source'); self.assertEqual(closed, [])
        result, closed = self.receive(data=data)
        self.assertEqual(result, 'custody_packet'); self.assertEqual(len(closed), 2)

    def validate(self, flags=os.O_RDONLY | os.O_DIRECTORY, fd_flags=1, **changes):
        value = custody(); value.update(changes)
        metas = [SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=10001, st_gid=10001,
                                 st_dev=3, st_ino=10+i) for i in range(2)]
        with patch.object(S.os, 'fstat', side_effect=metas), \
             patch.object(S.fcntl, 'fcntl', side_effect=[flags, fd_flags] * 2), \
             patch.object(S.os, 'readlink', side_effect=[value['root_path'], value['home_path']]), \
             patch.object(S.os.path, 'realpath', side_effect=AssertionError('root must not traverse private home')):
            return S.validate_received(value, [50, 51], custody()['original_monotonic_cutoff_ns'])

    def test_root_validates_fd_identity_without_private_path_traversal(self):
        self.assertEqual(self.validate(), custody())

    def test_writable_or_path_or_non_directory_fd_refused(self):
        for flags in (os.O_WRONLY | os.O_DIRECTORY, os.O_RDONLY,
                      os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_PATH', 0x200000)):
            with self.assertRaises(S.Rejected): self.validate(flags)

    def test_cloexec_required(self):
        with self.assertRaises(S.Rejected): self.validate(fd_flags=0)

    def test_not_immediate_child_and_passwd_injection_refused(self):
        for home in ('/another/home', '/ci-fixture/ui-original/sub/home',
                     '/ci-fixture/ui-original/home:root', '/ci-fixture/ui-original/home\n'):
            with self.assertRaises(S.Rejected): self.validate(home_path=home)

    def test_device_inode_exact(self):
        with self.assertRaises(S.Rejected): self.validate(home_inode=12)

    def test_strict_json_parser(self):
        for raw in (b'{"x":1,"x":2}', b'NaN', b'\xff'):
            with self.assertRaises(S.Rejected): S.loads(raw)

    def test_first_source_failure_survives_generic_and_cleanup_failure(self):
        first = S.FirstFailure()
        first.note('setup', 'setup_source', 'BirthEnroll', 'AuthorityAuthentication')
        first.note('setup', 'internal'); first.note('drain', 'cleanup_failed')
        self.assertEqual(first.value['source_boundary'], 'BirthEnroll')
        self.assertEqual(first.value['source_outcome'], 'AuthorityAuthentication')

    def test_source_error_is_immediate_and_closed(self):
        first = S.FirstFailure()
        with self.assertRaises(S.Rejected):
            S.setup_line(b'CI_UI_SETUP_FAILURE boundary=BirthEnroll outcome=AuthorityAuthentication', first)
        self.assertEqual(first.value['code'], 'setup_source')
        for line in (b'CI_UI_SETUP_FAILURE boundary=/secret outcome=AuthorityStorage',
                     b'CI_UI_SETUP_FAILURE boundary=BirthEnroll outcome=AuthorityInputWithinBound'):
            with self.assertRaises(S.Rejected): S.setup_line(line, S.FirstFailure())

    def test_lib_selector_requires_exact_one_test_shape(self):
        self.assertEqual(S.setup_line(b'running 1 test', S.FirstFailure()), 'running')
        self.assertEqual(S.setup_line(b'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 25 filtered out; finished in 1.25s', S.FirstFailure()), 'result')
        with self.assertRaises(S.Rejected):
            S.setup_line(b'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s', S.FirstFailure())
        self.assertEqual(S.setup_line(('test ' + S.SETUP_SELECTOR + ' ... ').encode() + S.READY, S.FirstFailure()), 'ready')

    def test_setup_status_preserves_exact_closed_exit_and_counts(self):
        for status in (-9, -6, 101, 127, 0):
            first = S.FirstFailure()
            counts = dict(ready=0, running=int(status != 127), result=0)
            with self.assertRaises(S.Rejected):
                S.validate_setup_result(status, counts, first)
            self.assertEqual(first.value['setup_observation'], dict(exit_status=status, **counts))
            first.note('drain', 'cleanup_failed')
            self.assertEqual(first.value['setup_observation']['exit_status'], status)

    def test_setup_success_requires_all_markers_and_zero_exit(self):
        first = S.FirstFailure()
        S.validate_setup_result(0, dict(ready=1, running=1, result=1), first)
        self.assertIsNone(first.value)
        with self.assertRaises(S.Rejected):
            S.validate_setup_result(101, dict(ready=1, running=1, result=1), first)

    def test_setup_observation_rejects_private_text_and_invalid_ranges(self):
        valid = dict(exit_status=101, ready=0, running=1, result=0)
        for key, value in (('exit_status', 'private text'), ('exit_status', True),
                           ('exit_status', -65), ('exit_status', 256), ('ready', 2), ('running', False)):
            bad = dict(valid); bad[key] = value
            with self.assertRaises(S.P.Rejected):
                S.P.failure('fixture', 'setup', 'setup_status', setup_observation=bad)
        for extra in ('path', 'stderr', 'secret'):
            with self.assertRaises(S.P.Rejected):
                S.P.failure('fixture', 'setup', 'setup_status', setup_observation={**valid, extra: 'private'})
        with self.assertRaises(S.P.Rejected):
            S.P.failure('fixture', 'append', 'setup_status', setup_observation=valid)

    def test_setup_error_wire_preserves_absence_and_rejects_null(self):
        value = S.P.failure('fixture', 'setup', 'internal')
        packet = S.error_packet(value)
        self.assertNotIn('setup_observation', packet)
        self.assertEqual(S.validate_error_packet(packet), value)
        with self.assertRaises(S.P.Rejected):
            S.validate_error_packet({**packet, 'setup_observation': None})
        value = S.P.failure('fixture', 'setup', 'setup_status',
            setup_observation=dict(exit_status=-9, ready=0, running=1, result=0))
        self.assertEqual(S.validate_error_packet(S.error_packet(value)), value)
        packet = S.error_packet(value); packet['setup_observation'] = None
        with self.assertRaises(S.P.Rejected):
            S.validate_error_packet(packet)

    def test_both_parent_pty_opens_never_acquire_controlling_terminal(self):
        # Source regression only: not proof of Linux PTY runtime behavior.
        root = pathlib.Path(__file__).parents[2]
        source = (root / 'crates/wholepact-native-host/src/host/manual_enrollment/command/'
                  'roster_publication_v2/sequential_construction_v3_qualification.rs').read_text()
        opens = re.findall(r'let slave = OpenOptions::new\(\)(.*?)\.open\(std::ffi::OsStr::from_bytes', source, re.S)
        self.assertEqual(len(opens), 2)
        self.assertTrue(all('.custom_flags(libc::O_NOCTTY)' in block for block in opens))
        self.assertEqual(source.count('libc::ioctl(0, libc::TIOCSCTTY, 0)'), 2)
        self.assertEqual(source.count('libc::setsid() < 0'), 2)
        self.assertNotIn('libc::SIG_IGN', source)

    def test_source_enum_allowlists_exact(self):
        root = pathlib.Path(__file__).parents[2]
        path = root / 'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/safe_diagnostics_v1.rs'
        source = path.read_text()
        excluded = {'Begin', 'Complete', 'AuthorityInputEmpty', 'AuthorityInputWithinBound', 'AuthorityInputOverBound'}
        for name, actual in (('Boundary', S.P.SETUP_BOUNDARIES), ('Outcome', S.P.SETUP_OUTCOMES)):
            body = re.search(r'labels!\s*\{\s*' + name + r'\s*\{(.*?)\}\s*\}', source, re.S).group(1)
            expected = set(re.findall(r'\b[A-Z][A-Za-z0-9]*\b', body))
            if name == 'Outcome': expected -= excluded
            self.assertEqual(actual, expected)


if __name__ == '__main__': unittest.main()
