#!/usr/bin/env python3
"""Credential-free compiled financial bundle. Import is inert; no downloads or execution.

A bundle is not authenticated by its own manifest. The caller must establish
GitHub repository/run/attempt/artifact provenance before accepting it. No API
credentials or runtime fixture files belong here. This helper only exports and
verifies the exact pre-credential compiler-selected binaries.
"""
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import tarfile

NAMES = ('coordinator-production', 'coordinator-observed', 'pristine-setup')
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 768 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{64}')
COMMIT = re.compile(r'[0-9a-f]{40}')
REPOSITORY = 'stanleykosi/pactloom'
RECIPE = dict(toolchain='1.99.0', rustc='rustc 1.99.0 (b940084d7 2026-09-28)',
    target='x86_64-unknown-linux-gnu', jobs=3, incremental=False,
    profile='release', default_features=False,
    coordinator_features='coordinated-financial-runtime',
    setup_features='durable-proposal,synthetic-born-joined-qualification',
    observed_rustflags='--cfg wholepact_financial_ci --cfg wholepact_financial_external_ci', production_rustflags='',
    setup_rustflags='', sqlcipher='4.19.0', openssl='3.5.9', static_crypto=True,
    platform='linux-amd64', locked=True,
    artifact_features={
        'coordinator-production':['common-image-bootstrap','coordinated-financial-runtime',
            'coordinated-financial-source-ui','coordinator-transient-password-input'],
        'coordinator-observed':['common-image-bootstrap','coordinated-financial-runtime',
            'coordinated-financial-source-ui','coordinator-transient-password-input'],
        'pristine-setup':['durable-proposal','financial-runtime','manual-admission',
            'synthetic-born-joined-qualification']})

class Rejected(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Rejected(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate_key')
        result[key] = value
    return result


def identity(value):
    need(type(value) is dict and set(value) == {'repository', 'source', 'source_tree', 'run_id', 'attempt'}, 'identity')
    need(value['repository'] == REPOSITORY and type(value['source']) is str and
         COMMIT.fullmatch(value['source']) and type(value['source_tree']) is str and
         COMMIT.fullmatch(value['source_tree']), 'identity')
    need(all(type(value[k]) is int and 1 <= value[k] <= (1 << 63) - 1 for k in ('run_id', 'attempt')), 'identity')
    return value


def closure(value):
    # Full tracked compile-input inventory supplied by the reviewed caller.
    need(type(value) is dict and 1 <= len(value) <= 50000, 'closure')
    for path, digest in value.items():
        need(type(path) is str and 0 < len(path) <= 1024 and
             re.fullmatch(r'[A-Za-z0-9_.+/-]+', path) and
             not path.startswith('/') and all(p not in ('', '.', '..') for p in path.split('/')),
             'closure_path')
        need(type(digest) is str and SHA.fullmatch(digest), 'closure_digest')
    return value


def file_pin(path):
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and 0 < meta.st_size <= MAX_FILE, 'file')
    with path.open('rb') as stream:
        need(stream.read(4) == b'\x7fELF', 'elf')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(size=meta.st_size, sha256=digest)


def validate_manifest(value, expected_identity, expected_closure):
    need(type(value) is dict and set(value) == {'version', 'identity', 'closure', 'recipe', 'files'}, 'manifest')
    need(type(value['version']) is int and value['version'] == 1, 'version')
    need(identity(value['identity']) == identity(expected_identity), 'provenance')
    need(closure(value['closure']) == closure(expected_closure), 'closure_mismatch')
    need(type(value['recipe']) is dict and canonical(value['recipe']) == canonical(RECIPE), 'recipe')
    need(type(value['files']) is dict and set(value['files']) == set(NAMES), 'file_set')
    total = 0
    for row in value['files'].values():
        need(type(row) is dict and set(row) == {'size', 'sha256'}, 'file_pin')
        need(type(row['size']) is int and 0 < row['size'] <= MAX_FILE and
             type(row['sha256']) is str and SHA.fullmatch(row['sha256']), 'file_pin')
        total += row['size']
    need(total <= MAX_TOTAL, 'total_size')
    return value


def export_bundle(artifacts, destination, producer, inputs):
    """Called before any fixture exists; exclusive output, exact four entries."""
    artifacts, destination = pathlib.Path(artifacts), pathlib.Path(destination)
    need({p.name for p in artifacts.iterdir()} == set(NAMES), 'file_set')
    value = dict(version=1, identity=identity(producer), closure=closure(inputs), recipe=RECIPE,
                 files={name: file_pin(artifacts / name) for name in NAMES})
    validate_manifest(value, producer, inputs)
    raw = canonical(value)
    need(len(raw) <= MAX_MANIFEST, 'manifest_size')
    with destination.open('xb') as output:
        with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            item = tarfile.TarInfo('manifest.json'); item.size = len(raw); item.mode = 0o444
            archive.addfile(item, io.BytesIO(raw))
            for name in NAMES:
                path = artifacts / name
                need(file_pin(path) == value['files'][name], 'changed_file')
                item = tarfile.TarInfo(name); item.size = value['files'][name]['size']; item.mode = 0o555
                with path.open('rb') as source:
                    archive.addfile(item, source)
        output.flush(); os.fsync(output.fileno())
    destination.chmod(0o444)
    # Revalidate the actual exported bytes, not just their original inputs.
    verify_bundle(destination, producer, inputs)
    return value


def verify_bundle(bundle, expected_identity, expected_closure):
    path = pathlib.Path(bundle)
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and
         0 < meta.st_size <= MAX_TOTAL + MAX_MANIFEST + 65536, 'bundle_file')
    with path.open('rb') as stream:
        value = None
        for index, name in enumerate(('manifest.json', *NAMES)):
            header = stream.read(512)
            need(len(header) == 512, 'archive_header')
            try:
                member = tarfile.TarInfo.frombuf(header, 'ascii', 'strict')
            except (tarfile.HeaderError, UnicodeError, ValueError):
                raise Rejected('archive_header') from None
            need(member.name == name and member.type == tarfile.REGTYPE and
                 member.uid == 0 and member.gid == 0 and member.uname == '' and
                 member.gname == '' and member.mtime == 0 and not member.linkname,
                 'archive_entry')
            if index == 0:
                need(0 < member.size <= MAX_MANIFEST and member.mode == 0o444, 'manifest_size')
                raw = stream.read(member.size)
                need(len(raw) == member.size, 'manifest_size')
                try:
                    value = json.loads(raw, object_pairs_hook=pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(Rejected('json')))
                except (ValueError, UnicodeError, RecursionError):
                    raise Rejected('json') from None
                need(canonical(value) == raw, 'canonical')
                validate_manifest(value, expected_identity, expected_closure)
            else:
                pin = value['files'][name]
                need(member.size == pin['size'] and member.mode == 0o555, 'archive_pin')
                remaining, digest = member.size, hashlib.sha256()
                first = True
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    need(chunk, 'archive_truncated')
                    if first:
                        need(chunk[:4] == b'\x7fELF', 'elf')
                        first = False
                    digest.update(chunk); remaining -= len(chunk)
                need(digest.hexdigest() == pin['sha256'], 'digest')
            padding = (-member.size) % 512
            need(stream.read(padding) == bytes(padding), 'archive_padding')
        content_end = stream.tell()
        expected_size = ((content_end + 1024 + 10239) // 10240) * 10240
        need(meta.st_size == expected_size and
             stream.read() == bytes(expected_size - content_end), 'archive_tail')
    return value
