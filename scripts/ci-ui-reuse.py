#!/usr/bin/env python3
"""Inactive pure provenance/source checks. No network, extraction or execution.

Inputs must come from the authenticated GitHub API for the explicitly pinned
same-repository producer, never from the bundle itself. These checks alone do
not authorize fetching/executing a bundle. No 'latest', discovery or fallback.
"""
import re

REPOSITORY = 'stanleykosi/pactloom'
BRANCH = 'qualification/durable-proposal-v1'
WORKFLOW = '.github/workflows/durable-native-linux.yml'
UPLOAD_STEP = 'Preserve exact credential-free compiled UI bundle'
SHA = re.compile('[0-9a-f]{64}')
COMMIT = re.compile('[0-9a-f]{40}')
MAX_ARCHIVE = 800 * 1024 * 1024
# Conservative: supervisor, compiler scripts, crates, Cargo and this verifier
# MUST stay identical. This is not a general 'scripts/**' bypass.
RUNTIME_ONLY = frozenset((
    WORKFLOW, 'scripts/qualification-gate-mode',
    'scripts/ci-ui-image.py', 'scripts/ci-ui-output.py',
    'scripts/ci-ui-container.py', 'scripts/ci-ui-setup-wrapper.py',
    'scripts/ci-ui-controller.py', 'scripts/ci-ui-weston-module.c',
    'scripts/ci-ui-prerequisite.py', 'scripts/ci-ui-reuse-pin.json',
    'scripts/tests/test_ci_ui_image.py', 'scripts/tests/test_ci_ui_output.py',
    'scripts/tests/test_ci_ui_container.py', 'scripts/tests/test_ci_ui_setup.py',
    'scripts/tests/test_ci_ui_controller.py', 'scripts/tests/test_ci_ui_prerequisite.py',
))

class Rejected(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Rejected(code)


def positive(value):
    return type(value) is int and 1 <= value <= (1 << 63) - 1


def validate_pin(pin):
    need(type(pin) is dict and set(pin) == {'version', 'repository', 'source', 'source_tree',
        'run_id', 'attempt', 'job_id', 'artifact_id', 'archive_sha256', 'bundle_sha256'}, 'pin')
    need(type(pin['version']) is int and pin['version'] == 1 and pin['repository'] == REPOSITORY, 'pin')
    need(all(type(pin[k]) is str and COMMIT.fullmatch(pin[k]) for k in ('source', 'source_tree')), 'source')
    need(all(positive(pin[k]) for k in ('run_id', 'attempt', 'job_id', 'artifact_id')), 'identity')
    need(all(type(pin[k]) is str and SHA.fullmatch(pin[k]) for k in ('archive_sha256', 'bundle_sha256')), 'digest')
    return pin


def validate_provenance(pin, run, job, artifact, source_tree):
    validate_pin(pin)
    need(all(type(x) is dict for x in (run, job, artifact)), 'records')
    need(source_tree == pin['source_tree'], 'tree')
    need(type(run.get('id')) is int and run['id'] == pin['run_id'] and
         type(run.get('run_attempt')) is int and run['run_attempt'] == pin['attempt'] and
         run.get('head_sha') == pin['source'] and run.get('head_branch') == BRANCH and
         run.get('event') == 'push' and run.get('status') == 'completed' and
         run.get('path') == WORKFLOW, 'run')
    for key in ('repository', 'head_repository'):
        need(type(run.get(key)) is dict and run[key].get('full_name') == REPOSITORY and
             positive(run[key].get('id')), 'repository')
    repo_id = run['repository']['id']
    need(run['head_repository']['id'] == repo_id, 'repository')
    need(type(job.get('id')) is int and job['id'] == pin['job_id'] and
         type(job.get('run_id')) is int and job['run_id'] == pin['run_id'] and
         type(job.get('run_attempt')) is int and job['run_attempt'] == pin['attempt'] and
         job.get('head_sha') == pin['source'] and job.get('name') == 'synthetic-only' and
         job.get('status') == 'completed', 'job')
    steps = job.get('steps')
    need(type(steps) is list and len(steps) <= 100, 'steps')
    uploads = [step for step in steps if type(step) is dict and step.get('name') == UPLOAD_STEP]
    need(len(uploads) == 1 and uploads[0].get('status') == 'completed' and
         uploads[0].get('conclusion') == 'success', 'upload')
    name = f"ui-build-{pin['run_id']}-{pin['attempt']}-{pin['source']}"
    need(type(artifact.get('id')) is int and artifact['id'] == pin['artifact_id'] and
         artifact.get('name') == name and artifact.get('expired') is False and
         type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_ARCHIVE and
         artifact.get('digest') == 'sha256:' + pin['archive_sha256'], 'artifact')
    owner = artifact.get('workflow_run')
    need(type(owner) is dict and type(owner.get('id')) is int and owner['id'] == pin['run_id'] and
         owner.get('head_sha') == pin['source'] and owner.get('head_branch') == BRANCH and
         type(owner.get('repository_id')) is int and owner['repository_id'] == repo_id and
         type(owner.get('head_repository_id')) is int and owner['head_repository_id'] == repo_id,
         'artifact_origin')
    # A failed runtime is allowed, not represented as a successful test. Only
    # the pre-credential binary upload must have succeeded on the exact attempt.
    return dict(repository=REPOSITORY, source=pin['source'], source_tree=pin['source_tree'],
                run_id=pin['run_id'], attempt=pin['attempt'])


def validate_closure(producer, consumer):
    for inventory in (producer, consumer):
        need(type(inventory) is dict and 1 <= len(inventory) <= 50000, 'closure')
        for path, digest in inventory.items():
            need(type(path) is str and 0 < len(path) <= 1024 and
                 re.fullmatch(r'[A-Za-z0-9_.+/-]+', path) and not path.startswith('/') and
                 all(part not in ('', '.', '..') for part in path.split('/')) and
                 type(digest) is str and SHA.fullmatch(digest), 'closure_entry')
    changed = {path for path in producer.keys() | consumer.keys() if producer.get(path) != consumer.get(path)}
    need(changed <= RUNTIME_ONLY, 'compile_inputs_changed')
    # Missing/new compiler inputs and altered compiler recipes are never ignored.
    need('Cargo.lock' in producer and 'Cargo.toml' in producer and
         'scripts/ci-ui-supervisor.py' in producer, 'compile_inputs_missing')
    return sorted(changed)
