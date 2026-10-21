#!/usr/bin/env python3
"""Pure fabricated-record and mocked-control tests. No product/process/socket run."""
import contextlib
import copy
import importlib.util
import io
import json
import pathlib
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
            elif event in ('birth', 'reaped'):
                detail = dict(child_role=item[1], child_pid=ids[item[1]])
                if event == 'reaped': detail.update(kind='exit', code=0)
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
    rows.append(root)
    fault = copy.deepcopy(target); fault.update(event='fault', detail=dict(name='wrong_role', phase='send_prepared'))
    rows.append(fault)
    for row in original:
        if row['role'] == 'Coordinator' and row['event'] == 'reaped':
            new = copy.deepcopy(row); new['detail'].update(kind='signal', code=9); rows.append(new)
    end = copy.deepcopy(rows[0]); end.update(event='finished', detail=dict(exit_code=1)); rows.append(end)
    for row in rows: row['case'] = 'wrong_role'
    return renumber(rows), [(4, 9), (5, 9)]


class Projection(unittest.TestCase):
    def check(self, rows):
        return P.validate_case('observed_success', rows, 78, [], 2)

    def refuse(self, rows):
        with self.assertRaises(P.Rejected):
            self.check(rows)

    def test_complete_source_graph(self):
        value = self.check(fixture())
        self.assertEqual((value['roles_ready'], value['birth_edges'], value['authenticated_receives'], value['owned_reaps']), (17, 16, 96, 16))
        self.assertNotIn('pid', json.dumps(value))
        self.assertNotIn('fds', json.dumps(value))

    def test_production_is_independent_and_silent(self):
        self.assertEqual(P.validate_case('production', [], 78, [], 2)['outcome'], 'passed')
        for rows, status, adopted in [(fixture(), 78, []), ([], 1, []), ([], 78, [(3, 0)])]:
            with self.assertRaises(P.Rejected):
                P.validate_case('production', rows, status, adopted, 2)

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
        with self.assertRaises(P.Rejected): P.validate_case('observed_success', fixture(), 78, [(20, 0)], 2)


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
        with self.assertRaises(P.Rejected): P.validate_case('wrong_role', rows, 1, [], 2)

    def test_closed_summary_no_cleanup_false_pass(self):
        value = self.check(fixture()); value['natural_empty'] = False
        with self.assertRaises(P.Rejected): P.validate_result(value, 'observed_success')

    def test_no_unknown_summary_data(self):
        value = self.check(fixture()); value['raw_error'] = 'DO_NOT_EMIT'
        with self.assertRaises(P.Rejected): P.validate_result(value, 'observed_success')


    def test_valid_negative_exact_cleanup(self):
        rows, adopted = packet_failure()
        value = P.validate_case('wrong_role', rows, 1, adopted, 2)
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
        with self.assertRaises(P.Rejected): P.validate_case('wrong_role', renumber(rows), 1, adopted, 2)

    def test_negative_fault_phase_exact(self):
        rows, adopted = packet_failure()
        next(r for r in rows if r['event'] == 'fault')['detail']['phase'] = 'send_released'
        with self.assertRaises(P.Rejected): P.validate_case('wrong_role', rows, 1, adopted, 2)

    def test_negative_adoption_is_exact_known_accounting(self):
        for change in ('unknown', 'duplicate', 'direct_duplicate', 'missing'):
            rows, adopted = packet_failure()
            if change == 'unknown': adopted.append((999, 9))
            elif change == 'duplicate': adopted.append(adopted[0])
            elif change == 'direct_duplicate': adopted.append((3, 9))
            else: adopted.pop()
            with self.assertRaises(P.Rejected): P.validate_case('wrong_role', rows, 1, adopted, 2)

    def test_negative_direct_reap_cannot_duplicate_or_disappear(self):
        for change in ('missing', 'duplicate'):
            rows, adopted = packet_failure()
            index = next(i for i, r in enumerate(rows) if r['event'] == 'reaped')
            if change == 'missing': rows.pop(index)
            else: rows.insert(index, copy.deepcopy(rows[index]))
            with self.assertRaises(P.Rejected): P.validate_case('wrong_role', renumber(rows), 1, adopted, 2)


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
        with self.assertRaises(P.Rejected): P.validate_case('observed_success', fixture() * 2, 78, [], 2)


class Supervisor(unittest.TestCase):
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

    def test_workflow_is_explicitly_bootstrap_only(self):
        text = (ROOT.parent / '.github/workflows/durable-native-linux.yml').read_text()
        self.assertIn("if: steps.mode.outputs.gate != 'bootstrap'", text)
        self.assertIn("if: steps.mode.outputs.gate == 'full' || steps.mode.outputs.gate == 'financial'", text)
        self.assertIn("if: always() && steps.mode.outputs.gate == 'bootstrap'", text)
        self.assertEqual((ROOT / 'qualification-gate-mode').read_bytes(), b'bootstrap\n')


if __name__ == '__main__':
    unittest.main()
