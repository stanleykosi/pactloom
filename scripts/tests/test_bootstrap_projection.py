#!/usr/bin/env python3
"""Pure fabricated-record and mocked-control tests. No product/process/socket run."""
import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).parents[1]
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
P = load('projection', 'ci-bootstrap-output.py')
S = load('supervisor', 'ci-bootstrap-supervisor.py')


def inspect_fixture():
    """Fabricated inspect using official v28.5.2 ContainerCreate canonical caps.

    This is not a captured CI65 inspect: that failed field was not retained.
    https://raw.githubusercontent.com/moby/moby/v28.5.2/client/container_create.go
    """
    return [dict(Config=dict(Labels={S.LABEL: 'token'}, Volumes=None, User=''),
                 HostConfig=dict(NetworkMode='none', ReadonlyRootfs=True, Privileged=False,
                     CapDrop=['ALL'], CapAdd=['CAP_SETGID', 'CAP_SETUID'],
                     SecurityOpt=['no-new-privileges:true'], PidsLimit=64, Memory=268435456,
                     Binds=None, Devices=[], Mounts=None, PidMode='', Tmpfs={
                         '/etc/wholepact': 'rw,noexec,nosuid,nodev,size=64k,mode=0755',
                         '/ci-evidence': 'rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700',
                         '/tmp': 'rw,noexec,nosuid,nodev,size=1m,mode=1777'}))]


class Isolation(unittest.TestCase):
    def inspect(self, rows, field=None):
        output = io.StringIO()
        with mock.patch.object(S, 'docker', return_value=json.dumps(rows).encode()), contextlib.redirect_stdout(output):
            if field is None:
                S.inspect_isolation('owned-name', 'token', 'production')
                self.assertEqual(output.getvalue(), '')
                return
            with self.assertRaises(S.Failure) as failed:
                S.inspect_isolation('owned-name', 'token', 'production')
        self.assertEqual(failed.exception.code, 'isolation_' + field)
        self.assertIn(failed.exception.code, P.CODES)
        self.assertNotIn('PRIVATE_SENTINEL', output.getvalue())
        prefix, raw = output.getvalue().strip().split(' ', 1)
        self.assertEqual(prefix, 'CI_BOOTSTRAP_ISOLATION_FAILURE')
        row = json.loads(raw)
        self.assertEqual(set(row), {'case', 'check', 'expected', 'observed', 'cleanup_pending'})
        self.assertEqual((row['case'], row['check'], row['cleanup_pending']), ('production', field, True))
        return row

    def test_canonical_capabilities_and_exact_aliases(self):
        for caps in (['CAP_SETGID', 'CAP_SETUID'], ['SETUID', 'SETGID'], ['SETGID', 'CAP_SETUID']):
            rows = inspect_fixture(); rows[0]['HostConfig']['CapAdd'] = caps
            self.inspect(rows)

    def test_capability_duplicates_extras_and_unknowns_fail_closed(self):
        for caps in (None, [], ['SETUID'], ['SETUID', 'SETUID'], ['SETUID', 'CAP_SETUID'],
                     ['SETUID', 'SETGID', 'SETPCAP'], ['CAP_SETUID', 'PRIVATE_SENTINEL'],
                     ['cap_setuid', 'CAP_SETGID'], [None, 'SETGID'], ['SETUID'] * 17):
            rows = inspect_fixture(); rows[0]['HostConfig']['CapAdd'] = caps
            self.inspect(rows, 'cap_add')

    def test_each_isolation_field_has_finite_failure(self):
        mutations = [
            ('inspect_shape', lambda rows: rows.clear()),
            ('config_shape', lambda rows: rows[0].update(Config=None)),
            ('run_label', lambda rows: rows[0]['Config'].update(Labels={S.LABEL: 'PRIVATE_SENTINEL'})),
            ('network', lambda rows: rows[0]['HostConfig'].update(NetworkMode='PRIVATE_SENTINEL')),
            ('readonly_root', lambda rows: rows[0]['HostConfig'].update(ReadonlyRootfs=False)),
            ('privileged', lambda rows: rows[0]['HostConfig'].update(Privileged=True)),
            ('cap_drop', lambda rows: rows[0]['HostConfig'].update(CapDrop=['PRIVATE_SENTINEL'])),
            ('no_new_privileges', lambda rows: rows[0]['HostConfig'].update(SecurityOpt=['no-new-privileges:false'])),
            ('pids_limit', lambda rows: rows[0]['HostConfig'].update(PidsLimit=65)),
            ('memory_limit', lambda rows: rows[0]['HostConfig'].update(Memory=268435457)),
            ('bind_mounts', lambda rows: rows[0]['HostConfig'].update(Binds=['PRIVATE_SENTINEL'])),
            ('devices', lambda rows: rows[0]['HostConfig'].update(Devices=[{'PathOnHost': 'PRIVATE_SENTINEL'}])),
            ('extra_mounts', lambda rows: rows[0]['HostConfig'].update(Mounts=['PRIVATE_SENTINEL'])),
            ('image_volumes', lambda rows: rows[0]['Config'].update(Volumes={'PRIVATE_SENTINEL': {}})),
            ('pid_namespace', lambda rows: rows[0]['HostConfig'].update(PidMode='PRIVATE_SENTINEL')),
            ('setup_user', lambda rows: rows[0]['Config'].update(User='PRIVATE_SENTINEL')),
            ('tmpfs_destinations', lambda rows: rows[0]['HostConfig']['Tmpfs'].update(PRIVATE_SENTINEL='private')),
            ('pin_tmpfs', lambda rows: rows[0]['HostConfig']['Tmpfs'].update({'/etc/wholepact': 'PRIVATE_SENTINEL'})),
            ('evidence_tmpfs', lambda rows: rows[0]['HostConfig']['Tmpfs'].update({'/ci-evidence': 'PRIVATE_SENTINEL'})),
            ('runtime_tmpfs', lambda rows: rows[0]['HostConfig']['Tmpfs'].update({'/tmp': 'PRIVATE_SENTINEL'})),
        ]
        for field, change in mutations:
            with self.subTest(field=field):
                rows = inspect_fixture(); change(rows); self.inspect(rows, field)

    def test_inspect_duplicate_keys_and_nonfinite_fail_closed(self):
        for raw in (b'[{"Config":{},"Config":{}}]', b'[NaN]'):
            output = io.StringIO()
            with mock.patch.object(S, 'docker', return_value=raw), contextlib.redirect_stdout(output):
                with self.assertRaises(S.Failure) as failed: S.inspect_isolation('owned-name', 'token', 'production')
            self.assertEqual(failed.exception.code, 'isolation_inspect_shape')
            self.assertIn('"observed":"invalid_json"', output.getvalue())

    def test_security_options_cannot_expand_privileges(self):
        for options in ([], ['no-new-privileges:true', 'seccomp=unconfined'],
                        ['no-new-privileges:true', 'apparmor=unconfined'],
                        ['no-new-privileges:true'] * 2, ['no-new-privileges=false']):
            rows = inspect_fixture(); rows[0]['HostConfig']['SecurityOpt'] = options
            self.inspect(rows, 'no_new_privileges')

    def test_tmpfs_options_exact_with_safe_projection(self):
        rows = inspect_fixture()
        value = rows[0]['HostConfig']['Tmpfs']['/ci-evidence']
        rows[0]['HostConfig']['Tmpfs']['/ci-evidence'] = ','.join(reversed(value.split(',')))
        self.inspect(rows)
        for changed in (value + ',rw', value.replace('noexec,', ''), value.replace('uid=10001', 'uid=0'),
                        value.replace('size=1m', 'size=PRIVATE_SENTINEL'), None):
            rows = inspect_fixture(); rows[0]['HostConfig']['Tmpfs']['/ci-evidence'] = changed
            row = self.inspect(rows, 'evidence_tmpfs')
            self.assertIn('uid=10001', row['expected'])

    def test_cleanup_only_never_emits_lifecycle_pass(self):
        for clean in (True, False):
            output = io.StringIO()
            with tempfile.TemporaryDirectory() as root, \
                 mock.patch.object(S, 'context', return_value=('a' * 40, 'token')), \
                 mock.patch.object(S, 'cleanup', return_value=clean), \
                 mock.patch.object(S.sys, 'argv', ['supervisor', 'cleanup']), \
                 mock.patch.dict(S.os.environ, {'RUNNER_TEMP': root}), contextlib.redirect_stdout(output):
                self.assertEqual(S.main(), 0 if clean else 1)
            prefix, raw = output.getvalue().strip().split(' ', 1)
            self.assertEqual(prefix, 'CI_BOOTSTRAP_CLEANUP_RESULT')
            row = json.loads(raw)
            self.assertEqual(row, dict(cleanup_passed=clean, cleanup_only=True,
                                       source='a' * 40, lifecycle_result='not_evaluated'))
            self.assertNotIn('CI_BOOTSTRAP_RESULT ', output.getvalue())


def fixture():
    ids = {role: index + 2 for index, role in enumerate(P.ROLES)}
    rows = []
    def add(role, event, **detail):
        parent = 'Host' if role in ('Signer1', 'Signer2') else 'Coordinator'
        rows.append(dict(schema_version=1, case='observed_success', event=event, role=role,
                         pid=ids[role], ppid=1 if role == 'Coordinator' else ids[parent],
                         sequence=1 + sum(r['pid'] == ids[role] for r in rows), elapsed_ms=1, detail=detail))
    for role in P.ROLES:
        parent = 'Host' if role in ('Signer1', 'Signer2') else 'Coordinator'
        for item in P.successful_order(role):
            event = item[0]
            if event == 'started': add(role, event, uid=10001, euid=10001)
            elif event == 'deadline': add(role, event, budget_ms=30000, deadline_elapsed_ms=30000)
            elif event == 'ready':
                count = 32 if role == 'Coordinator' else 9 if role == 'Host' else 5
                add(role, event, fds=list(range(count)), expected_fds=list(range(count)), fd_inventory_ok=True,
                    parent_pid=1 if role == 'Coordinator' else ids[parent], remaining_ms=29999, core_zero=True, dumpable_zero=True)
            elif event in ('birth', 'reaped', 'terminal_observed'):
                detail = dict(child_role=item[1], child_pid=ids[item[1]])
                if event in ('reaped', 'terminal_observed'): detail.update(kind='exit', code=0)
                add(role, event, **detail)
            elif event == 'received':
                add(role, event, kind=item[1], peer_role=item[2], peer_pid=ids[item[2]], sender_pid=ids[item[2]],
                    sender_uid=10001, peer_alive=True, remaining_ms=29999)
            elif event == 'release_decision': add(role, event, prepared=14)
            elif event == 'finished': add(role, event, exit_code=78 if role == 'Coordinator' else 0)
    return rows


def renumber(rows):
    counts = {}
    for row in rows:
        counts[row['pid']] = counts.get(row['pid'], 0) + 1
        row['sequence'] = counts[row['pid']]
    return rows


def packet_failure():
    original = fixture()
    rows = []
    for row in original:
        role, event = row['role'], row['event']
        keep = event in ('started', 'deadline', 'birth', 'ready')
        keep |= role == 'Host' and event == 'received' and row['detail']['kind'] == 'Prepared'
        keep |= role == 'Coordinator' and event == 'received' and row['detail']['kind'] == 'Prepared' and row['detail']['peer_role'] == 'Host'
        if keep: rows.append(copy.deepcopy(row))
    target = next(r for r in rows if r['role'] == 'Owner1BootstrapHistory')
    root = copy.deepcopy(rows[0])
    root.update(event='reject', detail=dict(boundary='packet', reason='shape', peer_role=target['role'],
                peer_pid=target['pid'], sender_pid=target['pid'], peer_alive=None,
                control_truncated=False, fd_inventory_restored=None))
    root['detail'].update(socket_hup=None, socket_error=None, socket_invalid=None)
    rows.append(root)
    fault = copy.deepcopy(target); fault.update(event='fault', detail=dict(name='wrong_role', phase='send_prepared'))
    rows.append(fault)
    for row in original:
        if row['role'] == 'Coordinator' and row['event'] == 'reaped':
            new = copy.deepcopy(row); new['detail'].update(kind='signal', code=9); terminal = copy.deepcopy(new); terminal['event'] = 'terminal_observed'; rows.extend((terminal, new))
    end = copy.deepcopy(rows[0]); end.update(event='finished', detail=dict(exit_code=1)); rows.append(end)
    for row in rows: row['case'] = 'wrong_role'
    return renumber(rows), [(4, 9), (5, 9)]


def lifecycle_failure(case, channel_loss=False):
    """Fabricated local causal prefixes, not captured runtime evidence."""
    original = fixture()
    target = 'Owner1BootstrapHistory'
    fault_role, phase = {
        'child_exit_after_released': (target, 'after_released'),
        'host_death': ('Host', 'after_signers_prepared'),
        'coordinator_death': ('Coordinator', 'after_all_prepared'),
        'timeout_before_prepared': ('CompletedPair', 'before_prepared'),
        'stall_after_stopped': (target, 'after_stopped'),
    }[case]
    rows = []
    for role in P.ROLES:
        own = [copy.deepcopy(row) for row in original if row['role'] == role]
        if case == 'stall_after_stopped':
            if role == 'Coordinator': own = [row for row in own if row['event'] not in ('terminal_observed', 'reaped', 'finished')]
            elif role == target: own = own[:3]  # READY, Release, Stop.
        else:
            last = ('ready',)
            if role == 'Coordinator':
                last = {'child_exit_after_released': ('received', 'Released', 'Host'),
                        'host_death': ('ready',), 'coordinator_death': ('release_decision',),
                        'timeout_before_prepared': ('received', 'Prepared', 'Owner2FinancialSigning')}[case]
            elif case == 'child_exit_after_released':
                last = ('received', 'Released', 'Signer2') if role == 'Host' else ('received', 'Release', 'Host' if role.startswith('Signer') else 'Coordinator')
            own = own[:1 + next(i for i, row in enumerate(own) if P.event_key(row) == last)]
        rows.extend(own)
    fault = copy.deepcopy(next(row for row in rows if row['role'] == fault_role))
    fault.update(event='fault', detail=dict(name=case, phase=phase))
    rows.append(fault)
    emitter = 'Host' if case == 'coordinator_death' else 'Coordinator'
    reject = copy.deepcopy(next(row for row in rows if row['role'] == emitter))
    peer = next(row for row in rows if row['role'] == fault_role)
    timeout = case in ('timeout_before_prepared', 'stall_after_stopped')
    reject.update(event='reject', detail=dict(
        boundary='deadline' if timeout else 'channel' if channel_loss else 'peer_lifetime',
        reason='original_deadline_expired' if timeout else 'lost' if channel_loss else 'dead_or_poll_error',
        peer_role=None if timeout else fault_role, peer_pid=None if timeout else peer['pid'], sender_pid=None,
        peer_alive=None if timeout or channel_loss else False, control_truncated=False, fd_inventory_restored=None,
        socket_hup=True if channel_loss else None, socket_error=False if channel_loss else None,
        socket_invalid=False if channel_loss else None))
    if timeout: reject['elapsed_ms'] = 30000
    rows.append(reject)
    if case != 'coordinator_death':
        for row in original:
            if row['role'] == 'Coordinator' and row['event'] == 'reaped':
                reap = copy.deepcopy(row)
                if case != 'stall_after_stopped' or reap['detail']['child_role'] == target:
                    reap['detail'].update(kind='signal', code=9)
                if timeout: reap['elapsed_ms'] = 30000
                terminal = copy.deepcopy(reap); terminal['event'] = 'terminal_observed'
                rows.extend((terminal, reap))
        finish = copy.deepcopy(original[0]); finish.update(event='finished', detail=dict(exit_code=1))
        if timeout: finish['elapsed_ms'] = 30000
        rows.append(finish)
    for row in rows: row['case'] = case
    adopted = [(4, 9), (5, 9)]
    if case == 'coordinator_death': adopted = [(pid, 256) for pid in range(3, 19)]
    if case == 'stall_after_stopped': adopted = []
    return renumber(rows), adopted, -9 if case == 'coordinator_death' else 1


class LifecycleProjection(unittest.TestCase):
    def check(self, case, rows, adopted, status):
        return P.validate_case(case, rows, status, adopted, 2, empty_verified=True)

    def test_exact_death_boundaries_both_kernel_observations(self):
        for case in ('child_exit_after_released', 'host_death', 'coordinator_death'):
            for channel in (False, True):
                with self.subTest(case=case, channel=channel):
                    rows, adopted, status = lifecycle_failure(case, channel)
                    self.assertEqual(self.check(case, rows, adopted, status)['outcome'], 'passed')

    def test_channel_alternate_requires_observed_hup_or_error_not_invalid(self):
        for case in ('child_exit_after_released', 'host_death', 'coordinator_death'):
            for flags in ((None, None, None), (False, False, False), (True, False, True), (False, True, True)):
                rows, adopted, status = lifecycle_failure(case, True)
                reject = next(row for row in rows if row['event'] == 'reject')
                reject['detail'].update(zip(('socket_hup', 'socket_error', 'socket_invalid'), flags))
                with self.assertRaises(P.Rejected): self.check(case, rows, adopted, status)
            rows, adopted, status = lifecycle_failure(case, True)
            next(row for row in rows if row['event'] == 'reject')['detail'].update(socket_hup=False, socket_error=True)
            self.assertEqual(self.check(case, rows, adopted, status)['outcome'], 'passed')

    def test_generic_channel_error_and_wrong_rejecting_role_cannot_qualify(self):
        for case in ('child_exit_after_released', 'host_death', 'coordinator_death'):
            for mutation in ('generic', 'wrong_role', 'wrong_peer'):
                rows, adopted, status = lifecycle_failure(case, True)
                reject = next(row for row in rows if row['event'] == 'reject')
                if mutation == 'generic': reject['detail'].update(reason='receive_failed', socket_hup=None, socket_error=None, socket_invalid=None)
                elif mutation == 'wrong_role': reject.update(role='Signer1', pid=4, ppid=3)
                else: reject['detail'].update(peer_role='Owner2FinancialSigning', peer_pid=17)
                with self.assertRaises(P.Rejected): self.check(case, renumber(rows), adopted, status)

    def test_dead_target_requires_exact_coordinator_sigkill_reap(self):
        for case in ('child_exit_after_released', 'host_death'):
            for kind, code in (('exit', 0), ('signal', 15)):
                rows, adopted, status = lifecycle_failure(case, True)
                target = next(row for row in rows if row['event'] == 'fault')['role']
                next(row for row in rows if row['event'] == 'reaped' and row['detail']['child_role'] == target)['detail'].update(kind=kind, code=code)
                with self.assertRaises(P.Rejected): self.check(case, rows, adopted, status)

    def test_child_death_requires_prior_prepared_and_no_stop_acceptance(self):
        case = 'child_exit_after_released'
        for mutation in ('missing_prepared', 'received_stop'):
            rows, adopted, status = lifecycle_failure(case, True)
            if mutation == 'missing_prepared':
                rows = [row for row in rows if not (row['role'] == 'Coordinator' and row['event'] == 'received'
                        and row['detail']['kind'] == 'Prepared' and row['detail']['peer_role'] == 'Owner1BootstrapHistory')]
            else:
                stop = copy.deepcopy(next(row for row in fixture() if row['role'] == 'Owner1BootstrapHistory'
                                          and row['event'] == 'received' and row['detail']['kind'] == 'Stop'))
                stop['case'] = case; rows.append(stop)
            with self.assertRaises(P.Rejected): self.check(case, renumber(rows), adopted, status)

    def test_timeout_original_deadline_and_exact_packet_prerequisites(self):
        for case in ('timeout_before_prepared', 'stall_after_stopped'):
            rows, adopted, status = lifecycle_failure(case)
            self.assertEqual(self.check(case, rows, adopted, status)['outcome'], 'passed')
            next(row for row in rows if row['event'] == 'reject')['elapsed_ms'] = 29900
            with self.assertRaises(P.Rejected): self.check(case, rows, adopted, status)
            rows, adopted, status = lifecycle_failure(case)
            if case == 'stall_after_stopped':
                rows = [row for row in rows if not (row['role'] == 'Coordinator' and row['event'] == 'received'
                        and row['detail']['kind'] == 'Stopped' and row['detail']['peer_role'] == 'Owner1BootstrapHistory')]
            else:
                prepared = copy.deepcopy(next(row for row in fixture() if row['role'] == 'Coordinator'
                        and row['event'] == 'received' and row['detail']['kind'] == 'Prepared' and row['detail']['peer_role'] == 'CompletedPair'))
                prepared['case'] = case
                rows.insert(next(i for i, row in enumerate(rows) if row['event'] == 'reject'), prepared)
            with self.assertRaises(P.Rejected): self.check(case, renumber(rows), adopted, status)

    def test_failure_observations_are_finite_and_preserve_original_boundary(self):
        rows, adopted, status = lifecycle_failure('child_exit_after_released', True)
        reject = next(row for row in rows if row['event'] == 'reject')
        reject['detail']['socket_invalid'] = True
        with self.assertRaises(P.Rejected) as failed: self.check('child_exit_after_released', rows, adopted, status)
        value = P.result('child_exit_after_released', 'error', 'evidence', failed.exception.code)
        value.update(P.observed_counts(rows, 'child_exit_after_released', adopted))
        P.validate_result(value, 'child_exit_after_released')
        self.assertEqual(value['code'], 'fault_boundary')
        self.assertTrue(value['rejection_observations'][0]['socket_invalid'])
        self.assertEqual(value['fault_observation'], dict(role='Owner1BootstrapHistory', phase='after_released'))
        self.assertEqual(value['fault_reap_observation'], dict(owner_role='Coordinator', child_role='Owner1BootstrapHistory', kind='signal', code=9))
        self.assertNotIn('pid', json.dumps(value))
        value['rejection_observations'][0]['raw_error'] = 'PRIVATE_SENTINEL'
        with self.assertRaises(P.Rejected): P.validate_result(value, 'child_exit_after_released')

    def test_duplicate_rejection_observations_are_explicitly_bounded(self):
        rows, adopted, _ = lifecycle_failure('child_exit_after_released', True)
        reject = next(row for row in rows if row['event'] == 'reject')
        rows = [copy.deepcopy(reject) for _ in range(256)]
        value = P.result('child_exit_after_released', 'error', 'evidence', 'sequence')
        value.update(P.observed_counts(rows, 'child_exit_after_released', adopted))
        self.assertEqual(P.validate_result(value, 'child_exit_after_released')['code'], 'sequence')
        self.assertEqual((len(value['rejection_observations']), value['rejection_observations_omitted']), (17, 239))
        self.assertLess(len(json.dumps(value).encode()), 8192)
        rows, adopted, status = lifecycle_failure('child_exit_after_released', True)
        value = self.check('child_exit_after_released', rows, adopted, status)
        value['rejection_observations_omitted'] = 1
        with self.assertRaises(P.Rejected): P.validate_result(value, 'child_exit_after_released')

    def test_public_result_schema_explicitly_excludes_historical_version(self):
        value = P.result('production', 'error', 'evidence', 'production_status')
        self.assertEqual(P.validate_result(value, 'production')['schema_version'], 3)
        for old in (1, 2):
            value['schema_version'] = old
            with self.assertRaises(P.Rejected): P.validate_result(value, 'production')


def interrupted_owner_fixture():
    rows, adopted, status = lifecycle_failure('timeout_before_prepared')
    host = copy.deepcopy(next(row for row in rows if row['role'] == 'Host'))
    host.update(event='terminal_observed', elapsed_ms=30000,
                detail=dict(child_role='Signer1', child_pid=4, kind='signal', code=9))
    rows.append(host)
    return renumber(rows), [(5, 9)], status


class TerminalObservation(unittest.TestCase):
    def check(self, rows, adopted, status=1, empty_verified=True):
        return P.validate_case('timeout_before_prepared', rows, status, adopted, 2, empty_verified=empty_verified)

    def test_interrupted_host_observation_is_not_an_owned_reap(self):
        rows, adopted, status = interrupted_owner_fixture()
        result = self.check(rows, adopted, status)
        self.assertEqual(result['outcome'], 'passed')
        self.assertEqual(result['owned_reaps'], 14)
        self.assertEqual(result['adopted_reaped'], 1)
        self.assertEqual(result['terminal_observed'], 15)
        self.assertEqual(result['owner_interrupted_terminal_roles'], ['Signer1'])
        self.assertEqual(result['reap_accounting']['post_reap_missing_roles'], ['Signer1'])
        self.assertEqual(result['host_terminal_observations'], [dict(owner_role='Host', child_role='Signer1', kind='signal', code=9)])
        self.assertNotIn('pid', json.dumps(result))

    def test_actual_adoption_after_terminal_requires_matching_status(self):
        rows, adopted, status = interrupted_owner_fixture()
        result = self.check(rows, [(4, 9)] + adopted, status)
        self.assertEqual(result['owner_interrupted_terminal_roles'], [])
        for wrong in (0, 256, 15, 127):
            with self.assertRaises(P.Rejected): self.check(rows, [(4, wrong)] + adopted)

    def test_actual_host_post_reap_after_terminal_remains_exclusive(self):
        rows, adopted, _ = interrupted_owner_fixture()
        post = copy.deepcopy(rows[-1]); post['event'] = 'reaped'; rows.append(post)
        result = self.check(renumber(rows), adopted)
        self.assertEqual(result['owned_reaps'], 15)
        self.assertEqual(result['owner_interrupted_terminal_roles'], [])
        with self.assertRaises(P.Rejected): self.check(rows, [(4, 9)] + adopted)
        rows[-1]['detail']['code'] = 15
        with self.assertRaises(P.Rejected): self.check(rows, adopted)

    def test_unexplained_missing_child_still_fails(self):
        rows, adopted, _ = interrupted_owner_fixture()
        rows.pop()
        with self.assertRaises(P.Rejected) as caught: self.check(rows, adopted)
        self.assertEqual(caught.exception.code, 'terminal_coverage')
        observed = P.observed_counts(rows, 'timeout_before_prepared', adopted, empty_verified=True)
        self.assertEqual(observed['reap_accounting']['post_reap_missing_roles'], ['Signer1'])
        self.assertEqual(observed['owner_interrupted_terminal_roles'], [])

    def test_missing_independent_echild_never_qualifies(self):
        rows, adopted, _ = interrupted_owner_fixture()
        for empty in (False, None, 1, 'true'):
            with self.assertRaises(P.Rejected) as caught: self.check(rows, adopted, empty_verified=empty)
            self.assertEqual(caught.exception.code, 'natural_empty_unverified')
        with self.assertRaises(P.Rejected): P.validate_case('production', [], 78, [], 2)
        source = (ROOT / 'ci-bootstrap-container.py').read_text()
        self.assertIn('except ChildProcessError:\n            return adopted, True', source)
        self.assertIn('child.pid, empty_verified=empty)', source)

    def test_wrong_owner_role_or_original_birth_cannot_supply_coverage(self):
        for mutation in ('owner', 'role', 'birth'):
            rows, adopted, _ = interrupted_owner_fixture()
            if mutation == 'owner': rows[-1].update(role='Coordinator', pid=2, ppid=1)
            elif mutation == 'role': rows[-1]['detail'].update(child_role='CompletedPair', child_pid=18)
            else:
                birth = next(row for row in rows if row['event'] == 'birth' and row['detail']['child_role'] == 'Signer1')
                birth.update(role='Coordinator', pid=2, ppid=1)
            with self.assertRaises(P.Rejected): self.check(renumber(rows), adopted)

    def test_missing_actual_host_sigkill_reap_cannot_supply_coverage(self):
        for kind, code in (('exit', 0), ('signal', 15)):
            rows, adopted, _ = interrupted_owner_fixture()
            for row in rows:
                if row['event'] in ('reaped', 'terminal_observed') and row['detail']['child_role'] == 'Host':
                    row['detail'].update(kind=kind, code=code)
            with self.assertRaises(P.Rejected) as caught: self.check(rows, adopted)
            self.assertEqual(caught.exception.code, 'terminal_coverage')

    def test_duplicates_unknown_adoptions_and_terminal_order_fail(self):
        for mutation in ('terminal_duplicate', 'direct_duplicate', 'adopted_duplicate', 'unknown', 'order'):
            rows, adopted, _ = interrupted_owner_fixture()
            if mutation == 'terminal_duplicate': rows.append(copy.deepcopy(rows[-1]))
            elif mutation == 'direct_duplicate': rows.append(copy.deepcopy(next(r for r in rows if r['event'] == 'reaped')))
            elif mutation == 'adopted_duplicate': adopted += adopted
            elif mutation == 'unknown': adopted.append((999, 0))
            else:
                first = next(i for i, r in enumerate(rows) if r['event'] == 'terminal_observed')
                rows[first], rows[first + 1] = rows[first + 1], rows[first]
            with self.assertRaises(P.Rejected): self.check(renumber(rows), adopted)

    def test_original_fault_and_deadline_remain_required(self):
        for mutation in ('renewed', 'wrong_fault', 'early'):
            rows, adopted, _ = interrupted_owner_fixture()
            if mutation == 'renewed': next(r for r in rows if r['event'] == 'deadline')['detail']['deadline_elapsed_ms'] = 45000
            elif mutation == 'wrong_fault': next(r for r in rows if r['event'] == 'fault')['detail']['phase'] = 'after_stopped'
            else: next(r for r in rows if r['event'] == 'reject')['elapsed_ms'] = 29900
            with self.assertRaises(P.Rejected): self.check(rows, adopted)

    def test_success_cannot_substitute_terminal_for_any_owned_reap(self):
        rows = fixture()
        rows = [row for row in rows if not (row['event'] == 'reaped' and row['detail']['child_role'] == 'Signer1')]
        with self.assertRaises(P.Rejected):
            P.validate_case('observed_success', renumber(rows), 78, [], 2, empty_verified=True)

    def test_schema3_terminal_fields_are_strict_and_bounded(self):
        rows, adopted, _ = interrupted_owner_fixture()
        result = self.check(rows, adopted)
        for field, bad in (('owner_interrupted_terminal_roles', ['Host']), ('terminal_observed', 257),
                           ('host_terminal_observations_omitted', 1)):
            changed = copy.deepcopy(result); changed[field] = bad
            with self.assertRaises(P.Rejected): P.validate_result(changed, 'timeout_before_prepared')
        self.assertLess(len(json.dumps(result).encode()), 8192)

    def test_profiles_are_explicit_and_historical_failure_not_relabelled(self):
        self.assertEqual(len(P.PROFILES['full-bootstrap-v1']), 15)
        self.assertEqual(len(P.PROFILES['ui-reap-prerequisite-v1']), 7)
        self.assertEqual(set(P.HISTORICAL_PACKET_EVIDENCE['cases']), set(P.CASES) - set(P.UI_REAP_CASES))
        self.assertEqual(P.HISTORICAL_PACKET_EVIDENCE['run_outcome'], 'failure')
        self.assertIs(P.HISTORICAL_PACKET_EVIDENCE['current_images_revalidated'], False)
        source = (ROOT / 'ci-bootstrap-supervisor.py').read_text()
        self.assertIn('for case in P.PROFILES[profile]:', source)
        self.assertIn('for case in P.PROFILES[profile])', source)
        self.assertIn("all_fifteen_current_images_verified=passed and profile == 'full-bootstrap-v1'", source)
        self.assertIn("set(manifest['images']) == set(P.PROFILES[manifest['profile']])", (ROOT / 'ci-bootstrap-container.py').read_text())


class Projection(unittest.TestCase):
    def check(self, rows):
        return P.validate_case('observed_success', rows, 78, [], 2, empty_verified=True)

    def refuse(self, rows):
        with self.assertRaises(P.Rejected):
            self.check(rows)

    def test_complete_source_graph(self):
        value = self.check(fixture())
        self.assertEqual((value['roles_ready'], value['birth_edges'], value['authenticated_receives'], value['owned_reaps']), (17, 16, 96, 16))
        self.assertNotIn('pid', json.dumps(value))
        self.assertNotIn('fds', json.dumps(value))

    def test_production_is_independent_and_silent(self):
        self.assertEqual(P.validate_case('production', [], 78, [], 2, empty_verified=True)['outcome'], 'passed')
        for rows, status, adopted in [(fixture(), 78, []), ([], 1, []), ([], 78, [(3, 0)])]:
            with self.assertRaises(P.Rejected):
                P.validate_case('production', rows, status, adopted, 2, empty_verified=True)

    def test_duplicate_json_keys(self):
        for raw in ('{"x":1,"x":2}', '{"d":{"x":1,"x":2}}'):
            with self.assertRaises(P.Rejected): P.loads(raw)

    def test_nonfinite_json(self):
        for value in ('NaN', 'Infinity', '-Infinity'):
            with self.assertRaises(P.Rejected): P.loads('{"x":' + value + '}')

    def test_noninteger_and_boolean_schema(self):
        for field, value in [('schema_version', True), ('schema_version', 1.0), ('pid', True), ('ppid', 0), ('elapsed_ms', 1.0)]:
            rows = fixture(); rows[0][field] = value; self.refuse(rows)

    def test_unknown_missing_fields(self):
        for which in ('common_extra', 'common_missing', 'detail_extra', 'detail_missing'):
            rows = fixture()
            if which == 'common_extra': rows[0]['secret'] = 'DO_NOT_EMIT'
            elif which == 'common_missing': del rows[0]['role']
            elif which == 'detail_extra': rows[0]['detail']['secret'] = 'DO_NOT_EMIT'
            else: del rows[0]['detail']['uid']
            self.refuse(rows)

    def test_duplicate_ready(self):
        rows = fixture(); rows.append(copy.deepcopy(next(r for r in rows if r['event'] == 'ready'))); self.refuse(rows)

    def test_duplicate_receive_and_missing_real_edge(self):
        rows = fixture(); received = [i for i, r in enumerate(rows) if r['event'] == 'received']
        rows[received[1]] = copy.deepcopy(rows[received[0]]); self.refuse(rows)

    def test_root_cannot_own_signer(self):
        rows = fixture(); row = next(r for r in rows if r['event'] == 'birth' and r['detail']['child_role'] == 'Signer1')
        row.update(role='Coordinator', pid=2, ppid=1); self.refuse(rows)

    def test_exact_fd_inventory_and_count(self):
        for change in ('different', 'extra', 'duplicate', 'false'):
            rows = fixture(); row = next(r for r in rows if r['event'] == 'ready')
            if change == 'different': row['detail']['fds'][-1] += 1
            elif change == 'extra': row['detail']['fds'].append(99); row['detail']['expected_fds'].append(99)
            elif change == 'duplicate': row['detail']['fds'][-1] = row['detail']['fds'][-2]
            else: row['detail']['fd_inventory_ok'] = False
            self.refuse(rows)

    def test_original_deadline_cannot_refresh(self):
        rows = fixture(); row = next(r for r in rows if r['event'] == 'received'); row['detail']['remaining_ms'] = 30000; row['elapsed_ms'] = 100; self.refuse(rows)

    def test_peer_identity_and_uid(self):
        for field, value in [('sender_pid', 999), ('sender_uid', 0), ('peer_alive', False), ('peer_role', 'Attacker')]:
            rows = fixture(); row = next(r for r in rows if r['event'] == 'received'); row['detail'][field] = value; self.refuse(rows)

    def test_no_success_after_signal_owned_reap(self):
        rows = fixture(); row = next(r for r in rows if r['event'] == 'reaped'); row['detail'].update(kind='signal', code=9); self.refuse(rows)

    def test_no_success_after_adoption(self):
        with self.assertRaises(P.Rejected): P.validate_case('observed_success', fixture(), 78, [(20, 0)], 2, empty_verified=True)


    def test_sequence_gaps_duplicates_and_reordering(self):
        for change in ('gap', 'duplicate', 'reorder'):
            rows = fixture()
            own = [i for i, r in enumerate(rows) if r['role'] == 'Coordinator']
            if change == 'gap': rows[own[1]]['sequence'] += 1
            elif change == 'duplicate': rows[own[1]]['sequence'] = 1
            else: rows[own[1]], rows[own[2]] = rows[own[2]], rows[own[1]]
            self.refuse(rows)

    def test_source_finish_count(self):
        rows = fixture(); rows.pop(); self.refuse(rows)

    def test_failure_cannot_be_only_exit_code(self):
        rows = fixture()
        for row in rows: row['case'] = 'wrong_role'
        with self.assertRaises(P.Rejected): P.validate_case('wrong_role', rows, 1, [], 2, empty_verified=True)

    def test_closed_summary_no_cleanup_false_pass(self):
        value = self.check(fixture()); value['natural_empty'] = False
        with self.assertRaises(P.Rejected): P.validate_result(value, 'observed_success')

    def test_no_unknown_summary_data(self):
        value = self.check(fixture()); value['raw_error'] = 'DO_NOT_EMIT'
        with self.assertRaises(P.Rejected): P.validate_result(value, 'observed_success')


    def test_valid_negative_exact_cleanup(self):
        rows, adopted = packet_failure()
        value = P.validate_case('wrong_role', rows, 1, adopted, 2, empty_verified=True)
        self.assertEqual(value['outcome'], 'passed')
        self.assertEqual(value['adopted_reaped'], 2)

    def test_causal_order_cannot_be_repaired_by_renumbering(self):
        rows = fixture()
        rows[0], rows[1] = rows[1], rows[0]
        self.refuse(renumber(rows))

    def test_negative_reject_must_be_real_coordinator_edge(self):
        rows, adopted = packet_failure()
        row = next(r for r in rows if r['event'] == 'reject')
        row.update(role='Host', pid=3, ppid=2)
        with self.assertRaises(P.Rejected): P.validate_case('wrong_role', renumber(rows), 1, adopted, 2, empty_verified=True)

    def test_negative_fault_phase_exact(self):
        rows, adopted = packet_failure()
        next(r for r in rows if r['event'] == 'fault')['detail']['phase'] = 'send_released'
        with self.assertRaises(P.Rejected): P.validate_case('wrong_role', rows, 1, adopted, 2, empty_verified=True)

    def test_negative_adoption_is_exact_known_accounting(self):
        for change in ('unknown', 'duplicate', 'direct_duplicate', 'missing'):
            rows, adopted = packet_failure()
            if change == 'unknown': adopted.append((999, 9))
            elif change == 'duplicate': adopted.append(adopted[0])
            elif change == 'direct_duplicate': adopted.append((3, 9))
            else: adopted.pop()
            with self.assertRaises(P.Rejected): P.validate_case('wrong_role', rows, 1, adopted, 2, empty_verified=True)

    def test_negative_direct_reap_cannot_duplicate_or_disappear(self):
        for change in ('missing', 'duplicate'):
            rows, adopted = packet_failure()
            index = next(i for i, r in enumerate(rows) if r['event'] == 'reaped')
            if change == 'missing': rows.pop(index)
            else: rows.insert(index, copy.deepcopy(rows[index]))
            with self.assertRaises(P.Rejected): P.validate_case('wrong_role', renumber(rows), 1, adopted, 2, empty_verified=True)


    def test_duplicate_observation_counts_preserve_original_failure(self):
        for event in ('ready', 'birth', 'received', 'reaped'):
            rows = fixture()
            rows.append(copy.deepcopy(next(row for row in rows if row['event'] == event)))
            try:
                self.check(rows)
            except P.Rejected as error:
                original = error.code
            else:
                self.fail('Duplicate observation unexpectedly accepted')
            value = P.result('observed_success', 'error', 'evidence', original)
            value.update(P.observed_counts(rows, 'observed_success', []))
            self.assertEqual(P.validate_result(value, 'observed_success')['code'], original)
            self.assertEqual(value['records'], len(rows))
            field = {'ready': 'roles_ready', 'birth': 'birth_edges', 'received': 'authenticated_receives', 'reaped': 'owned_reaps'}[event]
            self.assertEqual(value[field], {'ready': 18, 'birth': 17, 'received': 97, 'reaped': 17}[event])

    def test_error_count_bound_cannot_be_used_for_pass(self):
        for field, count in [('roles_ready', 18), ('birth_edges', 17), ('authenticated_receives', 97), ('owned_reaps', 17)]:
            value = P.result('wrong_role', 'passed', 'complete', 'none')
            value.update(natural_empty=True)
            value[field] = count
            with self.assertRaises(P.Rejected): P.validate_result(value, 'wrong_role')

    def test_bounded_records(self):
        with self.assertRaises(P.Rejected): P.validate_case('observed_success', fixture() * 2, 78, [], 2, empty_verified=True)


class Supervisor(unittest.TestCase):
    def test_actual_finite_reject_is_emitted_before_cleanup_and_retained(self):
        rows, adopted, _ = lifecycle_failure('child_exit_after_released', True)
        value = S.P.result('child_exit_after_released', 'error', 'evidence', 'fault_boundary')
        value.update(S.P.observed_counts(rows, 'child_exit_after_released', adopted))
        output = io.StringIO()
        def remove(*_args):
            self.assertIn('CI_BOOTSTRAP_CASE_FAILURE ', output.getvalue())
            self.assertIn('"socket_hup":true', output.getvalue())
            raise S.Failure('cleanup', 'container_remaining')
        with mock.patch.object(S, 'owned_names', return_value=[]), mock.patch.object(S, 'docker', return_value=b'id'), \
             mock.patch.object(S, 'inspect_isolation'), mock.patch.object(S, 'command', return_value=(1, json.dumps(value).encode())), \
             mock.patch.object(S, 'remove_container', side_effect=remove), \
             mock.patch.dict(S.os.environ, {'BOOTSTRAP_DOCKER_CONFIG': '/unused'}), contextlib.redirect_stdout(output):
            self.assertFalse(S.run_case('child_exit_after_released', 'tag', 'token'))
        self.assertNotIn('container_remaining', output.getvalue())
        lines = [json.loads(line.split(' ', 1)[1]) for line in output.getvalue().splitlines()]
        self.assertEqual([line['code'] for line in lines], ['fault_boundary', 'fault_boundary'])
        self.assertEqual(lines[0]['rejection_observations'], lines[1]['rejection_observations'])
        self.assertFalse(lines[1]['container_removed'])

    def test_client_timeout_still_removes_container_and_exposes_first_error(self):
        calls = []
        def remove(name, token):
            calls.append('remove')
            self.assertIn('CASE_FAILURE', output.getvalue())
            raise S.Failure('cleanup', 'container_remaining')
        output = io.StringIO()
        with mock.patch.object(S, 'owned_names', return_value=[]), mock.patch.object(S, 'docker', return_value=b'id'), \
             mock.patch.object(S, 'inspect_isolation'), mock.patch.object(S, 'command', side_effect=S.Failure('runtime', 'client_deadline')), \
             mock.patch.object(S, 'remove_container', side_effect=remove), mock.patch.dict(S.os.environ, {'BOOTSTRAP_DOCKER_CONFIG': '/unused'}), contextlib.redirect_stdout(output):
            self.assertFalse(S.run_case('production', 'tag', 'token'))
        self.assertEqual(calls, ['remove'])
        self.assertIn('"code":"client_deadline"', output.getvalue())
        self.assertNotIn('container_remaining', output.getvalue())
        self.assertIn('"container_removed":false', output.getvalue())

    def test_create_uncertainty_never_retries_create(self):
        output = io.StringIO()
        with mock.patch.object(S, 'owned_names', return_value=[]), \
             mock.patch.object(S, 'docker', side_effect=S.Failure('container', 'client_deadline')) as docker, \
             mock.patch.object(S, 'remove_container') as remove, contextlib.redirect_stdout(output):
            self.assertFalse(S.run_case('production', 'tag', 'token'))
        self.assertEqual(docker.call_count, 1)
        self.assertEqual(remove.call_count, 1)

    def test_success_requires_removal(self):
        result = S.P.result('production', 'passed', 'complete', 'none'); result['natural_empty'] = True
        output = io.StringIO()
        with mock.patch.object(S, 'owned_names', return_value=[]), mock.patch.object(S, 'docker', return_value=b'id'), \
             mock.patch.object(S, 'inspect_isolation'), mock.patch.object(S, 'command', return_value=(0, json.dumps(result).encode())), \
             mock.patch.object(S, 'remove_container', side_effect=S.Failure('cleanup', 'container_remaining')), \
             mock.patch.dict(S.os.environ, {'BOOTSTRAP_DOCKER_CONFIG': '/unused'}), contextlib.redirect_stdout(output):
            self.assertFalse(S.run_case('production', 'tag', 'token'))
        self.assertNotIn('"outcome":"passed"', output.getvalue())

    def test_workflow_has_explicit_full_or_ui_prerequisite_profiles(self):
        text = (ROOT.parent / '.github/workflows/durable-native-linux.yml').read_text()
        self.assertIn("if: steps.mode.outputs.gate != 'bootstrap'", text)
        self.assertIn("if: steps.mode.outputs.gate == 'full' || steps.mode.outputs.gate == 'financial'", text)
        self.assertIn("if: always() && (steps.mode.outputs.gate == 'bootstrap' || steps.mode.outputs.gate == 'ui')", text)
        self.assertIn('Seven current-image bootstrap reap/lifetime prerequisites', text)
        self.assertIn('CI69 remains failed', text)
        self.assertIn((ROOT / 'qualification-gate-mode').read_bytes(), (b'bootstrap\n', b'ui\n'))


if __name__ == '__main__':
    unittest.main()
