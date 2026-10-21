#!/usr/bin/env python3
"""Fabricated/source tests and bounded local Python subprocess checks.

No download, package install, compile, Docker or native product execution.
Network boundaries are mocked; generated-checker tests run fixed Python children
to check diagnostics, timeout and output bounds. The .deb-named test files contain
only fabricated ASCII in temporary directories. These checks do not establish
actual package installation or libweston ABI behavior.
"""
import ast
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import os
import pathlib
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location('private_ci_ui_image', ROOT / 'ci-ui-image.py')
I = importlib.util.module_from_spec(SPEC)
with mock.patch.object(subprocess, 'Popen') as no_process, \
        mock.patch.object(subprocess, 'run') as no_run, \
        mock.patch.object(socket, 'socket') as no_socket:
    SPEC.loader.exec_module(I)
    assert not no_process.called and not no_run.called and not no_socket.called
RAW = (ROOT / 'ci-ui-packages.json').read_bytes()
LOCK = I.validate_manifest(RAW)


def fabricated_record(content=b'fabricated, not a Debian package'):
    return {'name': 'fabricated', 'filename': 'fabricated_1_amd64.deb',
            'url': I.ARCHIVE_ORIGIN + 'pool/main/f/fabricated/fabricated_1_amd64.deb',
            'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}


def fabricated_tar(entries):
    """Entries: (relative path, bytes, optional tar type). Never a real tar fetch."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:') as tar:
        for entry in entries:
            name, content = entry[:2]
            info = tarfile.TarInfo(name)
            info.type = entry[2] if len(entry) > 2 else tarfile.REGTYPE
            info.size = len(content) if info.isreg() else 0
            if info.issym() or info.islnk():
                info.linkname = '/etc/passwd'
            tar.addfile(info, io.BytesIO(content) if info.isreg() else None)
    return lzma.compress(stream.getvalue())


def pin(content):
    return {'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}


def input_pins():
    return {name: pin(('fabricated ' + name).encode())
            for name in (*I.RUNTIME_FILES, *I.ARTIFACT_FILES, I.MODULE_SOURCE)}


def installer_definitions():
    # Load only generated definitions/constants. Discard the sys.exit entrypoint.
    # This interprets Python source, not native compilation or an image build.
    tree = ast.parse(I._INSTALL_SCRIPT)
    tree.body = [node for node in tree.body if not isinstance(node, ast.Expr)]
    namespace = {}
    exec(compile(tree, '<fabricated-helper-definitions>', 'exec'), namespace)
    return namespace


class RejectionTests(unittest.TestCase):
    def rejected(self, code, action):
        with self.assertRaises(I.Rejected) as found:
            action()
        self.assertEqual(found.exception.code, code)
        self.assertEqual(str(found.exception), code)


class LockValidation(RejectionTests):
    def test_reviewed_raw_lock_and_complete_counts(self):
        self.assertEqual(hashlib.sha256(RAW).hexdigest(), I.LOCK_SHA256)
        self.assertEqual(len(LOCK['base_packages']), 87)
        self.assertEqual(LOCK['sizes']['runtime']['new_packages'], 215)
        self.assertEqual(LOCK['sizes']['runtime']['download_bytes'], 149756396)
        self.assertEqual(LOCK['sizes']['build']['new_packages'], 256)
        self.assertEqual(LOCK['sizes']['build']['download_bytes'], 206055496)
        self.assertEqual(len(I.expected_packages(LOCK, 'runtime')), 302)
        self.assertEqual(len(I.expected_packages(LOCK, 'build')), 343)

    def test_raw_is_pinned_including_whitespace(self):
        for raw in (RAW + b'\n', RAW.replace(b'trixie', b'forked'), b'{}', b'{"a":1,"a":2}'):
            with self.subTest(raw=raw[:30]):
                self.rejected('manifest_pin', lambda: I.validate_manifest(raw))
        for raw in ('not bytes', b'', b'X' * (I.MAX_LOCK_BYTES + 1)):
            self.rejected('manifest_size', lambda: I.validate_manifest(raw))

    def test_duplicate_json_keys_rejected_without_native_parser(self):
        self.rejected('duplicate_key', lambda: I._unique([('same', 1), ('same', 2)]))

    def test_public_helpers_reject_mutated_validated_mapping(self):
        altered = copy.deepcopy(LOCK)
        altered['notes'].append('new instruction')
        for operation in (lambda: I.download_plan(altered),
                          lambda: I.expected_packages(altered, 'base'),
                          lambda: I.render_dockerfile(altered),
                          lambda: I.render_build_files(altered, input_pins())):
            self.rejected('manifest_pin', operation)

    def test_extra_or_recommends_field_not_accepted(self):
        for where, key in (('root', 'commands'), ('package', 'recommends')):
            altered = copy.deepcopy(LOCK)
            (altered if where == 'root' else altered['packages'][0])[key] = 'run arbitrary code'
            self.rejected('manifest_shape', lambda: I._validate_structure(altered))

    def test_no_alternate_base_origin_suite_or_architecture(self):
        for key, value in (('base_image', 'python:latest'), ('archive_origin', 'https://example.org/'),
                           ('suite', 'sid'), ('architecture', 'arm64')):
            altered = copy.deepcopy(LOCK)
            altered[key] = value
            self.rejected('manifest_origin', lambda: I._validate_structure(altered))

    def test_no_roots_expansion(self):
        altered = copy.deepcopy(LOCK)
        altered['roots']['runtime'].append('xwayland')
        self.rejected('roots', lambda: I._validate_structure(altered))

    def test_no_base_version_upgrade_or_downgrade(self):
        for value in ('3.5.1-1', '9.9.9-1'):
            altered = copy.deepcopy(LOCK)
            next(p for p in altered['packages'] if p['name'] == 'openssl')['version'] = value
            self.rejected('base_changed', lambda: I._validate_structure(altered))

    def test_base_download_forbidden_even_exact_version(self):
        altered = copy.deepcopy(LOCK)
        row = next(p for p in altered['packages'] if p['origin'] == 'pinned-base')
        row['size'] = 1
        self.rejected('base_changed', lambda: I._validate_structure(altered))

    def test_duplicate_base_or_package_rejected(self):
        for key in ('base_packages', 'packages'):
            altered = copy.deepcopy(LOCK)
            altered[key][1] = copy.deepcopy(altered[key][0])
            self.rejected('package_duplicate', lambda: I._validate_structure(altered))

    def test_paths_cannot_escape_or_redirect(self):
        for value in ('../bad.deb', 'pool/main/b/binutils/../../bad.deb',
                      'https://example.org/b.deb', 'pool/main/b/binutils/a%2fb.deb',
                      'pool/main/b/binutils/a.deb?x=secret'):
            altered = copy.deepcopy(LOCK)
            altered['packages'][0]['path'] = value
            self.rejected('package_path', lambda: I._validate_structure(altered))

    def test_bad_download_size_or_hash(self):
        for field, value in (('size', True), ('size', 0), ('size', 129 * 1024 * 1024),
                             ('sha256', 'A' * 64), ('sha256', '0' * 65)):
            altered = copy.deepcopy(LOCK)
            altered['packages'][0][field] = value
            self.rejected('package_size', lambda: I._validate_structure(altered))

    def test_missing_extra_duplicate_closure_names(self):
        for operation in (lambda x: x.pop(), lambda x: x.append('absent'), lambda x: x.append(x[0])):
            altered = copy.deepcopy(LOCK)
            operation(altered['closures']['runtime'])
            self.rejected('closure', lambda: I._validate_structure(altered))

    def test_declared_sums_checked(self):
        altered = copy.deepcopy(LOCK)
        altered['sizes']['runtime']['download_bytes'] += 1
        self.rejected('closure_size', lambda: I._validate_structure(altered))

    def test_dependency_versions_rechecked(self):
        altered = copy.deepcopy(LOCK)
        row = next(p for p in altered['packages'] if p['name'] == 'weston')
        row['depends'] += ', libc6 (>= 99.0)'
        self.rejected('dependency_missing', lambda: I._validate_structure(altered))

    def test_only_declared_dependencies_and_unique_virtuals(self):
        packages = {
            'root': {'depends': 'missing | virtual (>= 2)', 'pre_depends': 'early', 'provides': '', 'version': '1'},
            'provider': {'depends': '', 'pre_depends': '', 'provides': 'virtual (= 2)', 'version': '8'},
            'early': {'depends': '', 'pre_depends': '', 'provides': '', 'version': '1'},
            'unused': {'depends': '', 'pre_depends': '', 'provides': '', 'version': '1'},
        }
        self.assertEqual(I._closure(packages, ['root']), ['early', 'provider', 'root'])
        packages['provider']['provides'] = 'virtual'
        self.rejected('dependency_missing', lambda: I._closure(packages, ['root']))
        packages['provider']['provides'] = 'virtual (= 2)'
        packages['unused']['provides'] = 'virtual (= 2)'
        self.rejected('dependency_missing', lambda: I._closure(packages, ['root']))

    def test_unrecognized_dependency_grammar_fails_closed(self):
        for value in ('pkg [amd64]', 'pkg <profile>', 'pkg; run', 'pkg (>= 1) trailing', ''):
            self.rejected('dependency_grammar', lambda: I._dependency(value))

    def test_debian_version_order(self):
        for earlier, later in (('1.0~rc1', '1.0'), ('1.0', '1.0-1'), ('1.0-2', '1.0-10'),
                               ('1.0a', '1.0+'), ('1.0~~', '1.0~'), ('9.0', '1:1.0'),
                               ('3.5.7-1~deb13u2', '3.5.7-1~deb13u3')):
            self.assertLess(I.compare_versions(earlier, later), 0)
            self.assertGreater(I.compare_versions(later, earlier), 0)
        for left, right in (('1.0', '0:1.0-0'), ('1.01', '1.1'), ('1.0-01', '1.0-1')):
            self.assertEqual(I.compare_versions(left, right), 0)

    def test_installed_exact_base_and_stages(self):
        for stage in ('base', 'build', 'runtime'):
            output = ''.join(f'{name}\t{version}\t{arch}\tinstalled\n'
                             for name, (version, arch) in I.expected_packages(LOCK, stage).items())
            I.validate_installed(LOCK, stage, output)
            self.rejected('installed_packages', lambda: I.validate_installed(LOCK, stage, output.replace('3.5.7-1~deb13u3', '3.5.1-1')))
            self.rejected('installed_packages', lambda: I.validate_installed(LOCK, stage, output + 'extra\t1\tall\tinstalled\n'))
            self.rejected('installed_output', lambda: I.validate_installed(LOCK, stage, output + output))
            self.rejected('installed_output', lambda: I.validate_installed(LOCK, stage, output.replace('installed', 'config-files', 1)))
        self.rejected('stage', lambda: I.expected_packages(LOCK, 'other'))


class BoundedStaging(RejectionTests):
    def test_plan_has_union_not_double_downloads(self):
        plan = I.download_plan(LOCK)
        self.assertEqual(len(plan), 258)
        self.assertEqual(sum(p['size'] for p in plan), 207036460)
        self.assertEqual(len({p['filename'] for p in plan}), len(plan))
        self.assertNotIn('openssl', {p['name'] for p in plan})
        self.assertIn('seatd', {p['name'] for p in plan})
        self.assertNotIn('xwayland', {p['name'] for p in plan})
        self.assertTrue(all(p['url'].startswith('https://deb.debian.org/debian/pool/main/') for p in plan))

    def test_curl_no_config_no_redirects_no_retries_bounded(self):
        record = fabricated_record()
        cmd = I._curl_command(record, 17)
        self.assertEqual(cmd[:2], ['/usr/bin/curl', '-q'])
        self.assertEqual(cmd[-2:], ['--', record['url']])
        self.assertNotIn('--location', cmd)
        self.assertNotIn('-L', cmd)
        for key, value in (('--max-time', '17'), ('--max-filesize', str(record['size'])),
                           ('--connect-timeout', '15'), ('--retry', '0'), ('--proto', '=https'),
                           ('--noproxy', '*')):
            self.assertEqual(cmd[cmd.index(key) + 1], value)

    def test_download_boundaries_mocked_no_process(self):
        content = b'fabricated network bytes'
        record = fabricated_record(content)
        process = mock.Mock()
        process.wait.return_value = process.poll.return_value = 0
        process.stdout.fileno.return_value = 123
        selector = mock.MagicMock()
        selector.__enter__.return_value = selector
        selector.select.return_value = [('fabricated ready', 1)]
        stream = io.BytesIO()
        with mock.patch.object(I.subprocess, 'Popen', return_value=process) as start, \
                mock.patch.object(I.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(I.os, 'read', side_effect=[content[:5], content[5:], b'']):
            I._download(record, stream, 100, clock=lambda: 10)
        self.assertEqual(stream.getvalue(), content)
        self.assertFalse(process.kill.called)
        self.assertTrue(process.stdout.close.called)
        self.assertEqual(start.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.assertTrue(start.call_args.kwargs['close_fds'])

    def test_excess_short_mismatch_timeout_and_nonzero_fail_closed(self):
        content = b'fake'
        record = fabricated_record(content)
        cases = [('download_size', [content + b'!'], [1], 0),
                 ('download_digest', [b'fa', b''], [1], 0),
                 ('download_digest', [b'nope', b''], [1], 0),
                 ('download_timeout', [], [], 0),
                 ('download_failed', [content, b''], [1], 23)]
        for code, chunks, ready, exitcode in cases:
            with self.subTest(code=code, chunks=chunks):
                process = mock.Mock()
                process.wait.return_value = exitcode
                process.poll.return_value = None
                process.stdout.fileno.return_value = 123
                selector = mock.MagicMock()
                selector.__enter__.return_value = selector
                selector.select.return_value = ready
                output = io.BytesIO()
                with mock.patch.object(I.subprocess, 'Popen', return_value=process), \
                        mock.patch.object(I.selectors, 'DefaultSelector', return_value=selector), \
                        mock.patch.object(I.os, 'read', side_effect=chunks):
                    self.rejected(code, lambda: I._download(record, output, 100, clock=lambda: 10))
                self.assertLessEqual(len(output.getvalue()), record['size'])
                self.assertTrue(process.kill.called)
                self.assertTrue(process.stdout.close.called)

    def test_original_deadline_is_not_renewed(self):
        for deadline in (10, 9, 911, float('nan'), float('inf'), True):
            self.rejected('deadline', lambda: I._remaining(deadline, lambda: 10))
        self.assertEqual(I._remaining(11, lambda: 10), 1)
        self.assertEqual(I._remaining(11, lambda: 10.5), .5)

    def test_success_staging_only_fabricated_bytes_and_readonly(self):
        content = b'fabricated, not executable or an installable archive'
        record = fabricated_record(content)
        with tempfile.TemporaryDirectory() as root:
            target = pathlib.Path(root) / 'packages'
            with mock.patch.object(I, 'download_plan', return_value=(record,)), \
                    mock.patch.object(I, '_download', side_effect=lambda row, out, end: out.write(content)):
                result = I.stage_packages(LOCK, target, deadline=time.monotonic() + 10)
            self.assertEqual(result, {'files': 1, 'bytes': len(content)})
            path = target / record['filename']
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(path.stat().st_mode & 0o777, 0o444)
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_failure_cleans_new_staging_and_never_reuses_cache(self):
        with tempfile.TemporaryDirectory() as root:
            target = pathlib.Path(root) / 'packages'
            with mock.patch.object(I, 'download_plan', return_value=(fabricated_record(),)), \
                    mock.patch.object(I, '_download', side_effect=I.Rejected('download_digest')):
                self.rejected('download_digest', lambda: I.stage_packages(LOCK, target, deadline=time.monotonic() + 10))
            self.assertFalse(target.exists())
            target.mkdir()
            with self.assertRaises(FileExistsError):
                I._fresh_directory(target)

    def test_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root)
            (path / 'real').mkdir()
            (path / 'link').symlink_to(path / 'real', target_is_directory=True)
            self.rejected('staging_directory', lambda: I._fresh_directory(path / 'link' / 'new'))
        self.rejected('staging_directory', lambda: I._fresh_directory('relative'))


class HeaderSelection(RejectionTests):
    def test_exact_official_archive_and_five_pins(self):
        self.assertEqual(I.SOURCE_URL, 'https://deb.debian.org/debian/pool/main/w/weston/weston_14.0.2.orig.tar.xz')
        self.assertEqual(I.SOURCE_BYTES, 2043392)
        self.assertEqual(I.SOURCE_SHA256, 'b47216b3530da76d02a3a1acbf1846a9cd41d24caa86448f9c46f78f20b6e0ac')
        self.assertEqual(len(I.PRIVATE_HEADERS), 5)
        self.assertEqual(sum(size for size, sha in I.PRIVATE_HEADERS.values()), 69367)
        for size, sha in I.PRIVATE_HEADERS.values():
            self.assertTrue(I.SHA.fullmatch(sha))
            self.assertGreater(size, 0)
        self.rejected('source_digest', lambda: I._select_headers(b'not an upstream archive'))

    def test_selects_only_requested_headers_never_build_scripts(self):
        content = b'fabricated header'
        headers = {'libweston/example.h': (len(content), hashlib.sha256(content).hexdigest())}
        tar = fabricated_tar([('weston-14.0.2/libweston/example.h', content),
                              ('weston-14.0.2/meson.build', b'never execute'),
                              ('weston-14.0.2/ignored-link', b'', tarfile.SYMTYPE)])
        self.assertEqual(I._select_verified_headers(tar, headers), {'libweston/example.h': content})

    def test_duplicate_missing_wrong_size_digest_and_link_rejected(self):
        content = b'fake header'
        name = 'weston-14.0.2/libweston/example.h'
        headers = {'libweston/example.h': (len(content), hashlib.sha256(content).hexdigest())}
        for entries in ([], [(name, content), (name, content)], [(name, content + b'!')],
                        [(name, b'wrong bytes')], [(name, b'', tarfile.SYMTYPE)], [(name, b'', tarfile.LNKTYPE)]):
            self.rejected('source_header', lambda: I._select_verified_headers(fabricated_tar(entries), headers))

    def test_paths_outside_official_root_or_traversal_rejected(self):
        for name in ('/etc/passwd', '../escape', 'weston-14.0.2/../../escape',
                     'other-14.0.2/file', 'weston-14.0.2/bad\\path'):
            self.rejected('source_path', lambda: I._select_verified_headers(fabricated_tar([(name, b'x')]), {}))

    def test_compressed_and_member_bounds(self):
        tar = fabricated_tar([('weston-14.0.2/unused', b'X' * 2048)])
        with mock.patch.object(I, 'MAX_TAR_BYTES', 1024):
            self.rejected('source_limit', lambda: I._select_verified_headers(tar, {}))
        with mock.patch.object(I, 'MAX_TAR_ENTRIES', 0):
            self.rejected('source_limit', lambda: I._select_verified_headers(tar, {}))
        self.rejected('source_limit', lambda: I._select_verified_headers(tar + b'trailing', {}))
        self.rejected('source_archive', lambda: I._select_verified_headers(b'bad xz', {}))

    def test_staging_retains_headers_only_no_archive(self):
        selected = {'libweston/example.h': b'fabricated', 'libweston/backend-drm/example.h': b'fake'}
        with tempfile.TemporaryDirectory() as root:
            target = pathlib.Path(root) / 'headers'
            with mock.patch.object(I, '_download') as download, \
                    mock.patch.object(I, '_select_headers', return_value=selected):
                result = I.stage_private_headers(target, deadline=time.monotonic() + 10)
            self.assertEqual(result, {'files': 2, 'bytes': 14})
            self.assertEqual(download.call_args.args[0]['sha256'], I.SOURCE_SHA256)
            self.assertEqual({str(p.relative_to(target)) for p in target.rglob('*') if p.is_file()}, set(selected))
            self.assertTrue(all(p.suffix == '.h' for p in target.rglob('*') if p.is_file()))


class BuildSource(RejectionTests):
    def test_module_no_entrypoint_and_generated_helper_parses_only(self):
        source = (ROOT / 'ci-ui-image.py').read_text()
        tree = ast.parse(source)
        self.assertNotIn("if __name__ == '__main__'", source)
        self.assertFalse(any(isinstance(node, ast.If) for node in tree.body))
        ast.parse(I._INSTALL_SCRIPT)

    def test_dockerfile_fresh_exact_base_and_no_frontend_or_remote_sources(self):
        docker = I.render_dockerfile(LOCK)
        self.assertEqual(docker.count('FROM --platform=linux/amd64 ' + I.BASE_IMAGE), 2)
        self.assertNotIn('# syntax=', docker)
        self.assertNotIn('\nADD ', docker)
        self.assertNotIn('/opt/bootstrap', docker)
        self.assertNotIn('--privileged', docker)
        for line in docker.splitlines():
            if line.startswith('RUN '):
                self.assertIn('--network=none', line)
                for token in line.split():
                    if token.startswith('--mount='):
                        self.assertIn('type=bind,source=', token)
                        self.assertTrue(token.endswith(',readonly'))
                        self.assertNotIn('source=/', token)

    def test_fixed_copy_allowlist_no_headers_debs_or_tools(self):
        docker = I.render_dockerfile(LOCK)
        copies = [line for line in docker.splitlines() if line.startswith('COPY ')]
        self.assertEqual(len(copies), 9)
        self.assertIn('COPY --from=module-build --chown=0:0 --chmod=0444 /ci-output/ci-ui-weston-module.so /opt/ci-ui/ci-ui-weston-module.so', copies)
        for line in copies:
            self.assertNotIn('packages', line)
            self.assertNotIn('headers', line)
            self.assertNotIn('install.py', line)
            self.assertNotIn('*', line)
        for name in I.ARTIFACT_FILES:
            self.assertIn('COPY --chown=0:0 --chmod=0555 artifacts/' + name + ' /opt/ci-ui/' + name, copies)
        self.assertIn('USER 0:0', docker)
        self.assertIn('"/opt/ci-ui/ci-ui-container.py"', docker)

    def test_module_abi_link_options_and_only_local_source(self):
        docker = I.render_dockerfile(LOCK)
        source = I._INSTALL_SCRIPT
        for fragment in ('--no-undefined', '-z,relro,-z,now', '-fstack-protector-strong',
                         "['pkg-config', '--modversion', 'libweston-14']", "version == b'14.0.2\\n'",
                         "['libweston-14', 'wayland-server', 'pixman-1', 'xkbcommon']",
                         "['pkg-config', '--cflags', *names]", "['pkg-config', '--libs', *names]",
                         '/ci-inputs/ci-ui-weston-module.c', '-I/ci-headers/libweston'):
            self.assertIn(fragment, source)
        self.assertIn('/ci-build/install.py module', docker)
        self.assertNotIn('meson', docker)
        self.assertNotIn('cargo', docker)
        self.assertNotIn('curl', docker)
        self.assertNotIn('wget', docker)

    def test_rendered_metadata_and_strict_input_pins(self):
        files = I.render_build_files(LOCK, input_pins())
        self.assertEqual(set(files), {'Dockerfile', '.dockerignore', 'image-build/metadata.json', 'image-build/install.py',
                                      'final-build/metadata.json', 'final-build/install.py'})
        metadata = json.loads(files['image-build/metadata.json'])
        self.assertEqual(metadata['base'], I.expected_packages(LOCK, 'base'))
        self.assertEqual(len(metadata['packages']['runtime']), 215)
        self.assertEqual(len(metadata['packages']['build']), 256)
        self.assertEqual(set(metadata['inputs']), set(I.RUNTIME_FILES) | {I.MODULE_SOURCE})
        self.assertEqual(json.loads(files['final-build/metadata.json'])['inputs'], input_pins())
        self.assertEqual(set(metadata['headers']), set(I.PRIVATE_HEADERS))
        for alter in (lambda p: p.pop('pristine-setup'), lambda p: p.update({'unexpected': pin(b'x')})):
            pins = input_pins()
            alter(pins)
            self.rejected('input_allowlist', lambda: I.render_build_files(LOCK, pins))
        pins = input_pins()
        pins[I.MODULE_SOURCE]['sha256'] = 'not-a-digest'
        self.rejected('input_pin', lambda: I.render_build_files(LOCK, pins))

    def test_context_is_deny_by_default_exact_paths(self):
        ignore = I.render_build_files(LOCK, input_pins())['.dockerignore'].decode()
        self.assertTrue(ignore.startswith('**\n'))
        self.assertNotIn('!**', ignore)
        self.assertNotIn('!inputs/*', ignore)
        self.assertNotIn('.git', ignore)
        allowed = {line[1:] for line in ignore.splitlines() if line.startswith('!')}
        self.assertEqual({p for p in allowed if p.startswith('inputs/') and not p.endswith('/')},
                         {'inputs/' + name for name in (*I.RUNTIME_FILES, I.MODULE_SOURCE)})
        self.assertEqual({p for p in allowed if p.startswith('artifacts/') and not p.endswith('/')},
                         {'artifacts/' + name for name in I.ARTIFACT_FILES})
        self.assertEqual(len({p for p in allowed if p.endswith('.deb')}), 258)
        self.assertEqual(len({p for p in allowed if p.endswith('.h')}), 5)

    def test_generated_installer_locks_base_and_offline_exact_sets(self):
        source = I._INSTALL_SCRIPT
        before = source.index("need(installed() == meta['base'], 'base_package_set')")
        policy = source.index("policy.write_text('#!/bin/sh\\nexit 101\\n')")
        hold = source.index("checked(['apt-mark', 'hold'")
        install = source.index("checked(['apt-get'")
        after = source.index("need(installed() == meta[mode], 'installed_package_set')")
        self.assertLess(before, policy)
        self.assertLess(policy, hold)
        self.assertLess(hold, install)
        self.assertLess(install, after)
        for option in ('--no-download', '--no-install-recommends', '--no-install-suggests',
                       '--no-remove', '--no-upgrade', 'Dir::Etc::sourcelist=/dev/null', 'Dir::Etc::sourceparts=-'):
            self.assertIn(option, source)
        self.assertNotIn("'update'", source)
        self.assertNotIn('--allow-downgrades', source)
        self.assertNotIn('--allow-change-held-packages', source)
        self.assertIn("need(processes() <= before_processes, 'service_process')", source)
        self.assertIn("need(checked(['dpkg', '--audit'], capture=True) == b'', 'package_audit')", source)
        self.assertIn('stat.S_ISREG(meta.st_mode)', source)
        self.assertIn("hashlib.file_digest(stream, 'sha256')", source)

    def test_generated_account_no_uid_login_and_file_privilege_hardening(self):
        source = I._INSTALL_SCRIPT
        self.assertIn("ROOT = pathlib.Path('/opt/ci-ui')", source)
        self.assertLess(source.index("base_passwd = pathlib.Path('/etc/passwd').read_bytes()"),
                        source.index("checked(['apt-get'"))
        self.assertIn("(ROOT / 'base-passwd').chmod(0o444)", source)
        self.assertIn("symlink_to('/run/ci-account/passwd')", source)
        self.assertIn("fields[0] != 'wholepact-ci'", source)
        self.assertIn("fields[id_field] != '10001'", source)
        self.assertIn("wholepact-ci:x:10001:", source)
        self.assertNotIn('useradd', source)
        self.assertNotIn('chpasswd', source)
        self.assertNotIn('/etc/shadow', source)
        self.assertIn('stat.S_IMODE(meta.st_mode) & ~0o6000', source)
        self.assertIn("os.removexattr(path, 'security.capability'", source)
        self.assertIn("('/usr/include', '/usr/local/include')", source)
        self.assertNotIn('setcap cap_', source)
        self.assertNotIn('assert ', source)


class FirstFailureEvidence(RejectionTests):
    def test_downloader_original_error_survives_all_cleanup_failures(self):
        record = fabricated_record(b'fake')
        process = mock.Mock()
        process.poll.return_value = None
        process.kill.side_effect = OSError('private kill detail')
        process.wait.side_effect = subprocess.TimeoutExpired('private command', 5)
        process.stdout.close.side_effect = OSError('private close detail')
        selector = mock.MagicMock()
        selector.__enter__.return_value = selector
        selector.select.return_value = [1]
        with mock.patch.object(I.subprocess, 'Popen', return_value=process), \
                mock.patch.object(I.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(I.os, 'read', return_value=b'oversize'):
            with self.assertRaises(I.Rejected) as found:
                I._download(record, io.BytesIO(), 100, clock=lambda: 10)
        self.assertEqual(str(found.exception), 'download_size')
        self.assertTrue(found.exception.cleanup_failed)
        self.assertTrue(process.kill.called and process.wait.called and process.stdout.close.called)

    def test_successful_download_close_failure_has_separate_cleanup_code(self):
        record = fabricated_record(b'fake')
        process = mock.Mock()
        process.poll.return_value = process.wait.return_value = 0
        process.stdout.close.side_effect = OSError('private close detail')
        selector = mock.MagicMock()
        selector.__enter__.return_value = selector
        selector.select.return_value = [1]
        with mock.patch.object(I.subprocess, 'Popen', return_value=process), \
                mock.patch.object(I.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(I.os, 'read', side_effect=[b'fake', b'']):
            with self.assertRaises(I.Rejected) as found:
                I._download(record, io.BytesIO(), 100, clock=lambda: 10)
        self.assertEqual(str(found.exception), 'download_cleanup')
        self.assertTrue(found.exception.cleanup_failed)

    def test_package_unlink_failure_cannot_replace_download_code(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(I, 'download_plan', return_value=(fabricated_record(),)), \
                    mock.patch.object(I, '_download', side_effect=I.Rejected('download_digest')), \
                    mock.patch.object(I.pathlib.Path, 'unlink', side_effect=OSError('private unlink path')):
                with self.assertRaises(I.Rejected) as found:
                    I.stage_packages(LOCK, pathlib.Path(root) / 'packages', deadline=time.monotonic() + 10)
            self.assertEqual(str(found.exception), 'download_digest')
            self.assertTrue(found.exception.cleanup_failed)

    def test_header_rmdir_failure_cannot_replace_original_code(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(I, '_download'), \
                    mock.patch.object(I, '_select_headers', return_value={'libweston/example.h': b'fake'}), \
                    mock.patch.object(I, '_write_file', side_effect=I.Rejected('source_header')), \
                    mock.patch.object(I.pathlib.Path, 'rmdir', side_effect=OSError('private directory')):
                with self.assertRaises(I.Rejected) as found:
                    I.stage_private_headers(pathlib.Path(root) / 'headers', deadline=time.monotonic() + 10)
            self.assertEqual(str(found.exception), 'source_header')
            self.assertTrue(found.exception.cleanup_failed)

    def test_installer_finite_first_failure_survives_cleanup(self):
        helper = installer_definitions()
        helper['PHASE'], helper['CLEANUP'] = 'install', True
        helper['main'] = mock.Mock(side_effect=helper['Failed']('tool_exit'))
        helper['cleanup'] = mock.Mock(side_effect=OSError('private path and raw package error'))
        stderr = io.StringIO()
        with mock.patch.object(helper['sys'], 'stderr', stderr):
            self.assertEqual(helper['execute'](), 1)
        self.assertEqual(json.loads(stderr.getvalue()), {'schema_version': 1, 'phase': 'install',
                                                        'code': 'tool_exit', 'cleanup_failed': True})
        self.assertNotIn('private', stderr.getvalue())

    def test_installer_cleanup_only_and_unknown_failure_finite(self):
        for first, phase, code in ((None, 'cleanup', 'cleanup_failed'),
                                   (OSError('private input path'), 'inputs', 'internal')):
            helper = installer_definitions()
            helper['PHASE'], helper['CLEANUP'] = 'inputs', True
            helper['main'] = mock.Mock(side_effect=first)
            helper['cleanup'] = mock.Mock(side_effect=OSError('private cleanup'))
            stderr = io.StringIO()
            with mock.patch.object(helper['sys'], 'stderr', stderr):
                self.assertEqual(helper['execute'](), 1)
            self.assertEqual(json.loads(stderr.getvalue()), {'schema_version': 1, 'phase': phase,
                                                            'code': code, 'cleanup_failed': True})

    def test_installer_start_failure_keeps_finite_error_and_bounded_context(self):
        helper = installer_definitions()
        stderr = io.StringIO()
        with mock.patch.object(helper['subprocess'], 'Popen', side_effect=OSError('PRIVATE_ERROR')), \
             mock.patch.object(helper['sys'], 'stderr', stderr):
            with self.assertRaises(helper['Failed']) as found:
                helper['checked'](['apt-get', 'install'])
        self.assertEqual(found.exception.code, 'tool_start')
        row = json.loads(stderr.getvalue())
        self.assertEqual(row['tool'], 'apt-get')
        self.assertEqual(row['command'], ['apt-get', 'install'])
        self.assertFalse(row['command_truncated'])
        self.assertEqual(row['tail'], '')
        self.assertIsNone(row['exit_status'])
        self.assertNotIn('PRIVATE_ERROR', stderr.getvalue())

    def test_module_manifest_is_closed_deterministic_and_generated_after_compile(self):
        helper = installer_definitions()
        meta = {'inputs': input_pins(), 'build': {'fabricated-package': ['1', 'all']}}
        helper['installed'] = lambda: meta['build']
        with tempfile.TemporaryDirectory() as root:
            output = pathlib.Path(root) / 'output'
            original_path = pathlib.Path
            def fake_path(path):
                if path == '/ci-output':
                    return output
                raise AssertionError('unexpected filesystem target')
            def checked(args, capture=False):
                if args[:2] == ['pkg-config', '--modversion']:
                    return b'14.0.2\n'
                if args[:2] in (['pkg-config', '--cflags'], ['pkg-config', '--libs']):
                    return b''
                self.assertEqual(args[0], 'gcc')
                # Fabricated .so bytes, never an ELF/shared library or native compiler.
                (output / 'ci-ui-weston-module.so').write_bytes(b'not a compiled module')
                return None
            helper['checked'] = checked
            with mock.patch.object(helper['pathlib'], 'Path', side_effect=fake_path):
                helper['build_module'](meta)
            raw = (output / 'manifest.json').read_bytes()
            manifest = json.loads(raw)
            self.assertEqual(set(manifest), {'schema_version', 'package_lock_sha256', 'files'})
            self.assertEqual(manifest['schema_version'], 1)
            self.assertEqual(manifest['package_lock_sha256'], I.LOCK_SHA256)
            self.assertEqual(set(manifest['files']), set(I.RUNTIME_FILES) | {I.MODULE_BINARY})
            self.assertEqual(manifest['files'][I.MODULE_BINARY], pin(b'not a compiled module'))
            self.assertEqual((output / 'manifest.json').stat().st_mode & 0o777, 0o444)
            self.assertNotIn(I.MODULE_SOURCE, manifest['files'])
            self.assertNotIn('source_commit', manifest)


class FoundationAndDiagnosticTests(unittest.TestCase):
    def test_foundation_has_no_artifact_dependency_and_stays_identical(self):
        pins = input_pins()
        foundation = I.render_foundation_files(LOCK, {n: pins[n] for n in (*I.RUNTIME_FILES, I.MODULE_SOURCE)})
        final = I.render_build_files(LOCK, pins)
        self.assertEqual({k: final[k] for k in foundation}, foundation)
        altered = dict(pins)
        altered['coordinator-production'] = pin(b'new real compiled bytes')
        other = I.render_build_files(LOCK, altered)
        self.assertEqual({k: other[k] for k in foundation}, foundation)
        self.assertNotEqual(other['final-build/metadata.json'], final['final-build/metadata.json'])
        docker = foundation['Dockerfile'].decode()
        before, after = docker.split('FROM foundation AS runtime')
        self.assertNotIn('COPY --chown=0:0 --chmod=0555 artifacts/', before)
        self.assertIn('install.py finalize', after)
        self.assertNotIn('final-build/metadata.json', foundation)

    def test_final_manifest_requires_every_actual_file_and_original_script_pin(self):
        helper = installer_definitions()
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            helper['ROOT'] = root
            pins = input_pins()
            for name in (*I.RUNTIME_FILES, *I.ARTIFACT_FILES):
                (root / name).write_bytes(('fabricated ' + name).encode())
            (root / I.MODULE_BINARY).write_bytes(b'not an ELF module')
            foundation = {'schema_version': 1, 'package_lock_sha256': I.LOCK_SHA256,
                'files': {**{n: pins[n] for n in I.RUNTIME_FILES}, I.MODULE_BINARY: pin(b'not an ELF module')}}
            manifest_path = root / 'foundation-manifest.json'
            manifest_path.write_text(json.dumps(foundation))
            meta = {'runtime': {'fake': ['1', 'all']}, 'inputs': pins}
            helper['installed'] = lambda: meta['runtime']
            wrong = dict(meta, inputs=dict(pins))
            wrong['inputs'][I.RUNTIME_FILES[0]] = pin(b'changed after foundation')
            with self.assertRaises(helper['Failed']) as error:
                helper['finalize'](wrong)
            self.assertEqual(error.exception.code, 'input_digest')
            self.assertFalse((root / 'manifest.json').exists())
            helper['finalize'](meta)
            result = json.loads((root / 'manifest.json').read_bytes())
            self.assertEqual(set(result['files']), set(I.RUNTIME_FILES) | set(I.ARTIFACT_FILES) | {I.MODULE_BINARY})
            self.assertFalse(manifest_path.exists())
            self.assertEqual((root / 'manifest.json').stat().st_mode & 0o777, 0o444)

    def test_diagnostic_preserves_fixed_dpkg_format_but_rejects_other_controls(self):
        helper = installer_definitions()
        command = ['dpkg-query', '-W', '-f=${Package}\t${Version}\n']
        for actual, expected in ((command, command), (['dpkg-query', 'bad\x00arg'], [])):
            output = io.StringIO()
            with mock.patch.object(helper['sys'], 'stderr', output):
                helper['diagnostic'](actual, 'tool_exit', 1, b'error', 5, False)
            row = json.loads(output.getvalue())
            self.assertEqual(row['command'], expected)
            self.assertEqual(row['command_truncated'], not bool(expected))
            self.assertEqual(len(output.getvalue().splitlines()), 1)

    def test_generated_checker_retains_real_subprocess_stderr_and_status(self):
        helper = installer_definitions()
        stderr = io.StringIO()
        # Harmless Python child only: no package installation, Docker or native app.
        with mock.patch.object(helper['sys'], 'stderr', stderr):
            with self.assertRaises(helper['Failed']) as error:
                helper['checked']([sys.executable, '-c',
                    "import sys;print('package dependency missing',file=sys.stderr);print('password=example');sys.exit(7)"])
        row = json.loads(stderr.getvalue())
        self.assertEqual(error.exception.code, 'tool_exit')
        self.assertEqual(row['exit_status'], 7)
        self.assertIn('package dependency missing', row['tail'])
        self.assertNotIn('password=example', row['tail'])
        self.assertIn('[REDACTED]', row['tail'])
        self.assertFalse(row['tool_cleanup_failed'])

    def test_generated_checker_bounds_output_and_timeout(self):
        for code, expression, timeout in (
            ('tool_output_limit', "import sys;sys.stdout.write('x'*200000)", 5),
            ('tool_timeout', "import time;time.sleep(5)", .1)):
            helper = installer_definitions()
            helper['TOOL_TIMEOUT'] = timeout
            stderr = io.StringIO()
            with mock.patch.object(helper['sys'], 'stderr', stderr):
                with self.assertRaises(helper['Failed']) as error:
                    helper['checked']([sys.executable, '-c', expression], capture=True)
            row = json.loads(stderr.getvalue())
            self.assertEqual(error.exception.code, code)
            self.assertLessEqual(len(row['tail'].encode()), 65536)
            self.assertFalse(row['tool_cleanup_failed'])
            self.assertIsInstance(row['exit_status'], int)


if __name__ == '__main__':
    unittest.main()
