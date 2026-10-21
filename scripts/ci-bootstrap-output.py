#!/usr/bin/env python3
"""Pure finite bootstrap evidence validation. Private PID/FD facts never escape.

Public result schema 2 adds finite rejection/fault/reap observations. Historical
schema 1 results are not reinterpreted. Private record schema 1 remains an exact
source-pinned CI contract, not a public or backwards-compatible input format.
"""
import collections
import json
import re

SHA = re.compile(r'[0-9a-f]{40}')
RESULT_SCHEMA_VERSION = 2
PID_FILE = re.compile(r'[1-9][0-9]{0,9}\.jsonl')
CASES = ('production', 'observed_success', 'wrong_role', 'wrong_version', 'oversized_packet',
         'duplicate_prepared', 'rights', 'rights_truncated', 'later_wrong_sender', 'missing_credentials',
         'coordinator_death', 'host_death', 'child_exit_after_released', 'timeout_before_prepared', 'stall_after_stopped')
WITNESSES = tuple('Owner' + str(owner) + suffix for owner in (1, 2) for suffix in (
    'BootstrapHistory', 'V3DeliveryAdmission', 'DeliveryAuditHistory', 'FinancialReadHistory',
    'FinancialContinuationAdmission', 'FinancialSigning')) + ('CompletedPair',)
ROLES = ('Coordinator', 'Host', 'Signer1', 'Signer2') + WITNESSES
KINDS = ('Prepared', 'Release', 'Released', 'Stop', 'Stopped', 'Exit')
REASONS = {'packet': {'shape'}, 'ancillary': {'unexpected_control'},
           'credentials': {'missing', 'sender_mismatch'}, 'peer_lifetime': {'dead_or_poll_error'},
           'deadline': {'original_deadline_expired'}, 'channel': {'lost', 'send_failed', 'receive_failed'},
           'fd_inventory': {'unexpected_descriptor'}}
PHASES = {'pair_created', 'before_prepared', 'send_prepared', 'send_released', 'after_released',
          'after_all_prepared', 'after_signers_prepared', 'after_stopped'}
CODES = {'none', 'arguments', 'container_context', 'single_thread', 'manifest', 'image', 'pin',
         'identity', 'capabilities', 'evidence_setup', 'runtime_deadline', 'descendants_remain',
         'descendant_bound', 'evidence_limit', 'evidence_file', 'invalid_json', 'invalid_record',
         'case_evidence', 'production_status', 'unexpected_adoption', 'internal', 'container_create',
         'client_deadline', 'output_limit', 'command_failed', 'container_identity', 'container_remaining',
         'container_unverified', 'isolation', 'container_status', 'interrupted',
         'graph_identity', 'sequence', 'phase_order', 'deadline_binding', 'success_counts',
         'fault_identity', 'fault_boundary', 'root_finish', 'adoption_identity',
         'fixture_status', 'started_deadline', 'receive_identity', 'reap_identity'}
CODES |= {'isolation_' + field for field in (
    'inspect_shape', 'config_shape', 'run_label', 'network', 'readonly_root', 'privileged',
    'cap_drop', 'cap_add', 'no_new_privileges', 'pids_limit', 'memory_limit', 'bind_mounts',
    'devices', 'extra_mounts', 'image_volumes', 'pid_namespace', 'setup_user',
    'tmpfs_destinations', 'pin_tmpfs', 'evidence_tmpfs', 'runtime_tmpfs')}
STAGES = {'complete', 'setup', 'runtime', 'evidence', 'projection', 'container', 'cleanup', 'supervisor'}
RESULT_FIELDS = {'schema_version', 'case', 'outcome', 'stage', 'code', 'records', 'roles_ready',
                 'birth_edges', 'authenticated_receives', 'owned_reaps', 'adopted_reaped', 'natural_empty',
                 'elapsed_ms', 'financial_authority', 'ci_instrumented'}
OBSERVATION_FIELDS = ('rejection_observations', 'rejection_observations_omitted', 'fault_observation', 'fault_reap_observation')
RESULT_FIELDS.update(OBSERVATION_FIELDS)
REJECTION_PUBLIC = {'role', 'boundary', 'reason', 'peer_role', 'peer_alive', 'control_truncated',
                    'fd_inventory_restored', 'socket_hup', 'socket_error', 'socket_invalid'}
COMMON = {'schema_version', 'case', 'event', 'role', 'pid', 'ppid', 'sequence', 'elapsed_ms', 'detail'}
DETAIL = {
    'started': {'uid', 'euid'},
    'deadline': {'budget_ms', 'deadline_elapsed_ms'},
    'birth': {'child_role', 'child_pid'},
    'ready': {'fds', 'expected_fds', 'fd_inventory_ok', 'parent_pid', 'remaining_ms', 'core_zero', 'dumpable_zero'},
    'received': {'kind', 'peer_role', 'peer_pid', 'sender_pid', 'sender_uid', 'peer_alive', 'remaining_ms'},
    'release_decision': {'prepared'},
    'reject': (REJECTION_PUBLIC - {'role'}) | {'peer_pid', 'sender_pid'},
    'fault': {'name', 'phase'},
    'reaped': {'child_role', 'child_pid', 'kind', 'code'},
    'finished': {'exit_code'},
    'attacker_spawned': {'attacker_pid'},
    'attacker_sent': {'kind'},
    'attacker_reaped': {'attacker_pid', 'exit_code'},
}


class Rejected(Exception):
    def __init__(self, code):
        self.code = code if code in CODES else 'internal'


def need(ok, code='invalid_record'):
    if not ok:
        raise Rejected(code)


def number(value, minimum=0, maximum=45000):
    return type(value) is int and minimum <= value <= maximum


def pid(value):
    return number(value, 1, 2**31 - 1)


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'invalid_json')
        value[key] = item
    return value


def loads(raw):
    need(type(raw) in (bytes, str) and len(raw) <= 512 * 1024, 'invalid_json')
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected('invalid_json')))
    except (ValueError, UnicodeDecodeError, TypeError, RecursionError):
        raise Rejected('invalid_json') from None


def result(case, outcome, stage, code):
    need(case in CASES and outcome in ('passed', 'failed', 'error') and stage in STAGES and code in CODES)
    return dict(schema_version=RESULT_SCHEMA_VERSION, case=case, outcome=outcome, stage=stage, code=code,
                records=0, roles_ready=0, birth_edges=0, authenticated_receives=0, owned_reaps=0,
                adopted_reaped=0, natural_empty=False, elapsed_ms=0, financial_authority=False,
                ci_instrumented=case != 'production', rejection_observations=[], rejection_observations_omitted=0,
                fault_observation=None, fault_reap_observation=None)


def validate_result(row, case):
    need(type(row) is dict and set(row) == RESULT_FIELDS and type(row['schema_version']) is int
         and row['schema_version'] == RESULT_SCHEMA_VERSION and row['case'] == case and case in CASES)
    need(row['outcome'] in ('passed', 'failed', 'error') and row['stage'] in STAGES and row['code'] in CODES)
    for field, maximum in (('records', 256), ('roles_ready', 256), ('birth_edges', 256),
                           ('authenticated_receives', 256), ('owned_reaps', 256), ('adopted_reaped', 32), ('elapsed_ms', 60000)):
        need(number(row[field], 0, maximum))
    need(type(row['natural_empty']) is bool and row['financial_authority'] is False
         and row['ci_instrumented'] is (case != 'production'))
    observations = row['rejection_observations']
    observation_roles = ROLES + (('Attacker',) if case == 'later_wrong_sender' else ())
    need(type(observations) is list and len(observations) <= 17 and number(row['rejection_observations_omitted'], 0, 256))
    for observation in observations:
        need(type(observation) is dict and set(observation) == REJECTION_PUBLIC
             and observation['role'] in observation_roles)
        validate_rejection(observation)
    fault, reap = row['fault_observation'], row['fault_reap_observation']
    need(fault is None or (type(fault) is dict and set(fault) == {'role', 'phase'}
                          and fault['role'] in observation_roles and fault['phase'] in PHASES))
    need(reap is None or (type(reap) is dict and set(reap) == {'owner_role', 'child_role', 'kind', 'code'}
                         and reap['owner_role'] in observation_roles and reap['child_role'] in ROLES
                         and reap['kind'] in ('exit', 'signal') and number(reap['code'], 0, 127)))
    if row['outcome'] == 'passed' and case in ('production', 'observed_success'):
        need(not observations and row['rejection_observations_omitted'] == 0 and fault is None and reap is None)
    if row['outcome'] == 'passed':
        # Error rows contain exact observed counts (including malformed duplicate
        # observations) up to the record bound. Passing rows must satisfy the
        # much smaller fixed-graph limits and cannot exploit those error bounds.
        need(row['roles_ready'] <= 17 and row['birth_edges'] <= 16
             and row['authenticated_receives'] <= 96 and row['owned_reaps'] <= 16)
        need(row['rejection_observations_omitted'] == 0)
        need(row['stage'] == 'complete' and row['code'] == 'none' and row['natural_empty'] is True)
        if case in ('production', 'observed_success'):
            need(row['adopted_reaped'] == 0)
        if case == 'production':
            need(all(row[field] == 0 for field in ('records', 'roles_ready', 'birth_edges', 'authenticated_receives', 'owned_reaps')))
        if case == 'observed_success':
            need((row['roles_ready'], row['birth_edges'], row['authenticated_receives'], row['owned_reaps']) == (17, 16, 96, 16))
    else:
        need(row['stage'] != 'complete' and row['code'] != 'none')
    return row


def validate_rejection(d):
    need(d['boundary'] in REASONS and d['reason'] in REASONS[d['boundary']])
    need(d['peer_role'] is None or d['peer_role'] in ROLES)
    need(d['peer_alive'] is None or type(d['peer_alive']) is bool)
    need(type(d['control_truncated']) is bool)
    need(d['fd_inventory_restored'] is None or type(d['fd_inventory_restored']) is bool)
    flags = [d[key] for key in ('socket_hup', 'socket_error', 'socket_invalid')]
    need(all(flag is None for flag in flags) or
         (d['boundary'] == 'channel' and d['reason'] == 'lost' and all(type(flag) is bool for flag in flags)))


def validate_record(row, case):
    need(type(row) is dict and set(row) == COMMON and type(row['schema_version']) is int
         and row['schema_version'] == 1 and row['case'] == case)
    need(type(row['role']) is str and (row['role'] in ROLES or (case == 'later_wrong_sender' and row['role'] == 'Attacker')))
    need(pid(row['pid']) and pid(row['ppid']) and number(row['sequence'], 1, 256) and number(row['elapsed_ms']))
    event, d = row['event'], row['detail']
    need(type(event) is str and event in DETAIL and type(d) is dict and set(d) == DETAIL[event])
    if event == 'started':
        need(row['role'] == 'Coordinator' and d['uid'] == 10001 and type(d['uid']) is int
             and d['euid'] == 10001 and type(d['euid']) is int)
    elif event == 'deadline':
        need(row['role'] == 'Coordinator' and type(d['budget_ms']) is int and d['budget_ms'] == 30000
             and number(d['deadline_elapsed_ms'], 29990, 45000))
    elif event in ('birth', 'reaped'):
        need(d['child_role'] in ROLES and d['child_role'] != 'Coordinator' and pid(d['child_pid']))
        if event == 'reaped':
            need(d['kind'] in ('exit', 'signal') and number(d['code'], 0, 127))
    elif event == 'ready':
        for field in ('fds', 'expected_fds'):
            values = d[field]
            need(type(values) is list and len(values) <= 64 and all(number(x, 0, 1024) for x in values)
                 and values == sorted(set(values)))
        need(d['fds'] == d['expected_fds'] and d['fd_inventory_ok'] is True and d['core_zero'] is True
             and d['dumpable_zero'] is True and pid(d['parent_pid']) and number(d['remaining_ms'], 0, 30000))
        need(set((0, 1, 2)).issubset(d['fds']))
        need(len(d['fds']) == (32 if row['role'] == 'Coordinator' else 9 if row['role'] == 'Host' else 5))
    elif event == 'received':
        need(d['kind'] in KINDS and d['peer_role'] in ROLES and pid(d['peer_pid']) and pid(d['sender_pid'])
             and type(d['sender_uid']) is int and d['sender_uid'] == 10001 and d['peer_alive'] is True
             and number(d['remaining_ms'], 0, 30000) and d['sender_pid'] == d['peer_pid'])
    elif event == 'release_decision':
        need(row['role'] == 'Coordinator' and type(d['prepared']) is int and d['prepared'] == 14)
    elif event == 'reject':
        validate_rejection(d)
        need(d['peer_pid'] is None or pid(d['peer_pid']))
        need(d['sender_pid'] is None or pid(d['sender_pid']))
    elif event == 'fault':
        need(case not in ('production', 'observed_success') and d['name'] == case and d['phase'] in PHASES)
    elif event == 'finished':
        need(type(d['exit_code']) is int and d['exit_code'] in (0, 1, 78))
    elif event == 'attacker_spawned':
        need(case == 'later_wrong_sender' and pid(d['attacker_pid']))
    elif event == 'attacker_sent':
        need(case == 'later_wrong_sender' and row['role'] == 'Attacker' and d['kind'] == 'Released')
    elif event == 'attacker_reaped':
        need(case == 'later_wrong_sender' and pid(d['attacker_pid']) and type(d['exit_code']) is int and d['exit_code'] == 0)
    return row


def observed_counts(rows, case, adopted):
    need(type(rows) is list and len(rows) <= 256 and type(adopted) is list and len(adopted) <= 32, 'evidence_limit')
    for row in rows:
        validate_record(row, case)
    rejects = [row for row in rows if row['event'] == 'reject']
    rejects.sort(key=lambda row: ((ROLES + ('Attacker',)).index(row['role']), row['sequence']))
    observations = [dict(role=row['role'], **{key: row['detail'][key] for key in REJECTION_PUBLIC - {'role'}})
                    for row in rejects[:17]]
    faults = [row for row in rows if row['event'] == 'fault']
    fault = faults[0] if len(faults) == 1 else None
    reaps = [row for row in rows if row['event'] == 'reaped' and fault is not None
             and row['detail']['child_pid'] == fault['pid'] and row['detail']['child_role'] == fault['role']]
    reap = reaps[0] if len(reaps) == 1 else None
    return dict(records=len(rows), roles_ready=sum(row['event'] == 'ready' for row in rows),
                birth_edges=sum(row['event'] == 'birth' for row in rows),
                authenticated_receives=sum(row['event'] == 'received' for row in rows),
                owned_reaps=sum(row['event'] == 'reaped' for row in rows),
                adopted_reaped=len(adopted), natural_empty=True,
                rejection_observations=observations, rejection_observations_omitted=max(0, len(rejects) - 17),
                fault_observation=None if fault is None else dict(role=fault['role'], phase=fault['detail']['phase']),
                fault_reap_observation=None if reap is None else dict(owner_role=reap['role'],
                    **{key: reap['detail'][key] for key in ('child_role', 'kind', 'code')}))


def successful_order(role):
    def rec(kind, peer): return ('received', kind, peer)
    if role == 'Coordinator':
        children = ('Host',) + WITNESSES
        return ([('started',), ('deadline',)] + [('birth', child) for child in children] + [('ready',)]
                + [rec('Prepared', child) for child in children] + [('release_decision',)]
                + [rec(kind, child) for kind in ('Released', 'Stopped') for child in children]
                + [('reaped', child) for child in children] + [('finished',)])
    if role == 'Host':
        children = ('Signer1', 'Signer2')
        return ([('birth', child) for child in children] + [rec('Prepared', child) for child in children]
                + [('ready',), rec('Release', 'Coordinator')] + [rec('Released', child) for child in children]
                + [rec('Stop', 'Coordinator')] + [rec('Stopped', child) for child in children]
                + [rec('Exit', 'Coordinator')] + [('reaped', child) for child in children] + [('finished',)])
    parent = 'Host' if role in ('Signer1', 'Signer2') else 'Coordinator'
    return [('ready',)] + [rec(kind, parent) for kind in ('Release', 'Stop', 'Exit')] + [('finished',)]


def event_key(row):
    event, d = row['event'], row['detail']
    if event == 'received': return (event, d['kind'], d['peer_role'])
    if event in ('birth', 'reaped'): return (event, d['child_role'])
    return (event,)


def validate_case(case, rows, status, adopted, root_pid):
    need(case in CASES and type(rows) is list and len(rows) <= 256 and number(status, -127, 255)
         and type(adopted) is list and len(adopted) <= 32 and pid(root_pid), 'arguments')
    if case == 'production':
        need(status == 78 and not rows, 'production_status')
        need(not adopted, 'unexpected_adoption')
        out = result(case, 'passed', 'complete', 'none')
        out['natural_empty'] = True
        return out
    for row in rows:
        validate_record(row, case)
    by = collections.defaultdict(list)
    roles = {}
    process_roles = {}
    for row in rows:
        by[row['event']].append(row)
        need(row['pid'] not in process_roles or process_roles[row['pid']] == row['role'], 'graph_identity')
        process_roles[row['pid']] = row['role']
        need(row['role'] not in roles or roles[row['role']] == row['pid'], 'graph_identity')
        roles[row['role']] = row['pid']
    # A child can be killed before its first observation. The original parent's
    # birth record still binds that edge; do not invent an observation for it.
    for row in by['birth']:
        role, child = row['detail']['child_role'], row['detail']['child_pid']
        need(role not in roles or roles[role] == child, 'graph_identity')
        need(child not in process_roles or process_roles[child] == role, 'graph_identity')
        roles[role] = child
        process_roles[child] = role
    need(roles.get('Coordinator') == root_pid and len(by['started']) == 1 and len(by['deadline']) == 1, 'started_deadline')
    for process in process_roles:
        own = [row for row in rows if row['pid'] == process]
        need([row['sequence'] for row in own] == list(range(1, len(own) + 1)), 'sequence')
        need([row['elapsed_ms'] for row in own] == sorted(row['elapsed_ms'] for row in own), 'sequence')
    deadline = by['deadline'][0]['detail']['deadline_elapsed_ms']
    for row in by['ready'] + by['received']:
        need(abs(row['elapsed_ms'] + row['detail']['remaining_ms'] - deadline) <= 10, 'deadline_binding')
    # All recorded parent/child edges and receives must agree with the actual
    # fixed role graph. No root-direct signer or sibling credential substitution.
    def parent(role):
        return 'Host' if role in ('Signer1', 'Signer2') else 'Coordinator'
    need(len({row['detail']['child_pid'] for row in by['birth']}) == len(by['birth']), 'graph_identity')
    need(len({(row['pid'], row['detail']['kind'], row['detail']['peer_pid']) for row in by['received']})
         == len(by['received']), 'receive_identity')
    # The source records only the first rejection in each process. A second
    # convenient boundary cannot hide an earlier unrelated failure.
    need(len({row['pid'] for row in by['reject']}) == len(by['reject']), 'sequence')
    for row in by['birth'] + by['reaped']:
        d = row['detail']
        need(parent(d['child_role']) == row['role'] and roles.get(d['child_role']) == d['child_pid'], 'graph_identity')
    for row in by['reject']:
        d = row['detail']
        need((d['peer_role'] is None) == (d['peer_pid'] is None), 'graph_identity')
        if d['peer_role'] is not None:
            need(roles.get(d['peer_role']) == d['peer_pid'] and
                 (parent(row['role']) == d['peer_role'] or parent(d['peer_role']) == row['role']), 'graph_identity')
    for row in by['received']:
        d = row['detail']
        need(roles.get(d['peer_role']) == d['peer_pid'] and
             (parent(row['role']) == d['peer_role'] or parent(d['peer_role']) == row['role']), 'graph_identity')
    for row in by['ready']:
        expected_parent = 1 if row['role'] == 'Coordinator' else roles.get(parent(row['role']))
        need(row['detail']['parent_pid'] == expected_parent, 'graph_identity')
    need(len({row['role'] for row in by['ready']}) == len(by['ready']), 'graph_identity')
    if case == 'observed_success':
        need(status == 78 and not adopted and not by['fault'] and not by['reject'], 'fixture_status')
        need(set(roles) == set(ROLES) and len(by['ready']) == 17 and len(by['birth']) == 16
             and len(by['reaped']) == 16 and len(by['received']) == 96 and len(by['release_decision']) == 1
             and len(by['finished']) == 17, 'success_counts')
        for role in ROLES:
            need([event_key(row) for row in rows if row['role'] == role] == successful_order(role), 'phase_order')
        expected_edges = {(roles[parent(role)], roles[role]) for role in ROLES if role != 'Coordinator'}
        need({(row['pid'], row['detail']['child_pid']) for row in by['birth']} == expected_edges, 'graph_identity')
        need({(row['pid'], row['detail']['child_pid']) for row in by['reaped']} == expected_edges
             and all(row['detail']['kind'] == 'exit' and row['detail']['code'] == 0 for row in by['reaped']), 'reap_identity')
        expected_received = {(p, kind, c) for p, c in expected_edges for kind in ('Prepared', 'Released', 'Stopped')}
        expected_received |= {(c, kind, p) for p, c in expected_edges for kind in ('Release', 'Stop', 'Exit')}
        need({(row['pid'], row['detail']['kind'], row['detail']['peer_pid']) for row in by['received']} == expected_received, 'receive_identity')
        need({row['role'] for row in by['finished']} == set(ROLES)
             and all(row['detail']['exit_code'] == (78 if row['role'] == 'Coordinator' else 0) for row in by['finished']), 'root_finish')
        for row in rows:
            need(row['ppid'] == (1 if row['role'] == 'Coordinator' else roles[parent(row['role'])]), 'graph_identity')
        for row in by['ready']:
            need(row['detail']['parent_pid'] == row['ppid'], 'graph_identity')
    else:
        need(status == (-9 if case == 'coordinator_death' else 1) and len(by['fault']) == 1 and by['reject'], 'fixture_status')
        target = 'Owner1BootstrapHistory'
        expected_fault = {
            'missing_credentials': ('Coordinator', 'pair_created'),
            'coordinator_death': ('Coordinator', 'after_all_prepared'),
            'host_death': ('Host', 'after_signers_prepared'),
            'timeout_before_prepared': ('CompletedPair', 'before_prepared'),
            'later_wrong_sender': (target, 'send_released'),
            'child_exit_after_released': (target, 'after_released'),
            'stall_after_stopped': (target, 'after_stopped'),
        }.get(case, (target, 'send_prepared'))
        need((by['fault'][0]['role'], by['fault'][0]['detail']['phase']) == expected_fault, 'fault_identity')
        fault = by['fault'][0]
        before_fault = [event_key(row) for row in rows if row['pid'] == fault['pid'] and row['sequence'] < fault['sequence']]
        if case == 'coordinator_death':
            expected = successful_order('Coordinator')
            need(before_fault == expected[:expected.index(('release_decision',)) + 1], 'phase_order')
        elif case == 'host_death':
            expected = successful_order('Host')
            need(before_fault == expected[:expected.index(('ready',)) + 1], 'phase_order')
        elif case == 'missing_credentials':
            need(before_fault == [('started',), ('deadline',), ('birth', 'Host')], 'phase_order')
        else:
            expected = [('ready',)]
            if case in ('later_wrong_sender', 'child_exit_after_released', 'stall_after_stopped'):
                expected.append(('received', 'Release', 'Coordinator'))
            if case == 'stall_after_stopped': expected.append(('received', 'Stop', 'Coordinator'))
            need(before_fault == expected, 'phase_order')
        root_finish = [row for row in by['finished'] if row['role'] == 'Coordinator']
        need((not root_finish) if case == 'coordinator_death' else
             (len(root_finish) == 1 and root_finish[0]['detail']['exit_code'] == 1), 'root_finish')
        rejected = [row for row in by['reject']]
        def match(boundary, reason=None, **fields):
            coordinator_only = case in ('wrong_role', 'wrong_version', 'oversized_packet', 'duplicate_prepared',
                                        'rights', 'rights_truncated', 'later_wrong_sender', 'missing_credentials')
            return [row for row in rejected if (not coordinator_only or row['role'] == 'Coordinator')
                    and row['detail']['boundary'] == boundary
                    and (reason is None or row['detail']['reason'] == reason)
                    and all(row['detail'].get(k) == v for k, v in fields.items())]
        def original_loss(peer_role, rejecting_roles):
            # Socket closure may precede pidfd readability. Only actual HUP/ERR
            # is accepted; NVAL, generic I/O failure and a later inferred death
            # cannot stand in for this maintained boundary.
            found = match('peer_lifetime', 'dead_or_poll_error', peer_role=peer_role, peer_alive=False)
            found += [row for row in match('channel', 'lost', peer_role=peer_role, socket_invalid=False)
                      if row['detail']['socket_hup'] is True or row['detail']['socket_error'] is True]
            return [row for row in found if row['role'] in rejecting_roles]
        def coordinator_reaped_sigkill(role):
            return any(row['role'] == 'Coordinator' and row['detail']['child_role'] == role
                       and row['detail']['kind'] == 'signal' and row['detail']['code'] == 9 for row in by['reaped'])
        if case in ('wrong_role', 'wrong_version', 'oversized_packet', 'duplicate_prepared'):
            need(match('packet', 'shape', peer_role=target), 'fault_boundary')
        elif case in ('rights', 'rights_truncated'):
            need(match('ancillary', 'unexpected_control', peer_role=target, fd_inventory_restored=True,
                       **({'control_truncated': True} if case == 'rights_truncated' else {})), 'fault_boundary')
        elif case == 'later_wrong_sender':
            need(len(by['attacker_spawned']) == len(by['attacker_sent']) == len(by['attacker_reaped']) == 1, 'fault_boundary')
            attacker = by['attacker_spawned'][0]['detail']['attacker_pid']
            need(by['attacker_spawned'][0]['role'] == target and by['attacker_reaped'][0]['role'] == target
                 and fault['sequence'] < by['attacker_spawned'][0]['sequence'] < by['attacker_reaped'][0]['sequence'], 'fault_boundary')
            need(by['attacker_sent'][0]['pid'] == attacker and by['attacker_reaped'][0]['detail']['attacker_pid'] == attacker
                 and match('credentials', 'sender_mismatch', peer_role=target, sender_pid=attacker, peer_alive=True), 'fault_boundary')
        elif case == 'missing_credentials':
            need(match('credentials', 'missing', peer_role=target), 'fault_boundary')
        elif case == 'coordinator_death':
            need(original_loss('Coordinator', ('Host',) + WITNESSES), 'fault_boundary')
        elif case == 'host_death':
            need(original_loss('Host', ('Coordinator',)) and coordinator_reaped_sigkill('Host'), 'fault_boundary')
        elif case == 'child_exit_after_released':
            target = by['fault'][0]['role']
            losses = original_loss(target, ('Coordinator',))
            need(target in WITNESSES and losses and coordinator_reaped_sigkill(target), 'fault_boundary')
            prepared = [row for row in by['received'] if row['role'] == 'Coordinator'
                        and row['detail']['kind'] == 'Prepared' and row['detail']['peer_role'] == target]
            need(len(prepared) == len(by['release_decision']) == 1
                 and prepared[0]['sequence'] < by['release_decision'][0]['sequence'] < losses[0]['sequence'], 'fault_boundary')
            need(any(row['role'] == target and row['detail']['kind'] == 'Release' for row in by['received'])
                 and not any(row['role'] == target and row['detail']['kind'] == 'Stop' for row in by['received']), 'fault_boundary')
        elif case in ('timeout_before_prepared', 'stall_after_stopped'):
            root_deadlines = [row for row in match('deadline', 'original_deadline_expired')
                              if row['role'] == 'Coordinator' and row['elapsed_ms'] >= deadline - 10]
            need(len(root_deadlines) == 1, 'fault_boundary')
            if case == 'stall_after_stopped':
                target = by['fault'][0]['role']
                need(target in WITNESSES and coordinator_reaped_sigkill(target)
                     and any(row['role'] == 'Coordinator' and row['detail']['kind'] == 'Stopped'
                             and row['detail']['peer_role'] == target
                             and row['sequence'] < root_deadlines[0]['sequence'] for row in by['received']), 'fault_boundary')
            else:
                need(not any(row['role'] == 'Coordinator' and row['detail']['kind'] == 'Prepared'
                             and row['detail']['peer_role'] == 'CompletedPair' for row in by['received']), 'fault_boundary')
        # Orphans are accepted only for explicit error/death fixtures and always
        # shown distinctly from the product's original-owner reaps.
        need(all(type(item) is tuple and len(item) == 2 and pid(item[0]) and type(item[1]) is int
                 and item[0] in process_roles and item[0] != root_pid for item in adopted), 'adoption_identity')
        need(len({item[0] for item in adopted}) == len(adopted), 'adoption_identity')
        direct = [row['detail']['child_pid'] for row in by['reaped']]
        need(len(set(direct)) == len(direct), 'adoption_identity')
        adopted_ids = {item[0] for item in adopted}
        need(not (adopted_ids & set(direct)), 'adoption_identity')
        attackers = {row['detail']['attacker_pid'] for row in by['attacker_reaped']}
        need(not (attackers & (adopted_ids | set(direct))), 'adoption_identity')
        need(set(process_roles) - {root_pid} == set(direct) | adopted_ids | attackers, 'adoption_identity')
    out = result(case, 'passed', 'complete', 'none')
    out.update(observed_counts(rows, case, adopted))
    return validate_result(out, case)
