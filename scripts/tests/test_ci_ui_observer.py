"""Pure fabricated observer/controller/audit JSON. No real process or fixture."""
import copy
import importlib.util
import json
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location('ci_ui_observer_output', pathlib.Path(__file__).parents[1] / 'ci-ui-output.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
C, W = 'Coordinator', 'Owner1V3DeliveryAdmission'
D, EFFECT, REQUEST, NONCE, OWNER = (x * 64 for x in 'abcde')
RECT = dict(left=0.0, top=0.0, right=100.0, bottom=100.0)


def receipt(sequence, commit, frame, input_sequence):
    return dict(sequence=sequence, commit=commit, frame=frame, input_sequence=input_sequence)


def fabricated(case='cancel', *, first_failure=False):
    """Explicitly synthetic data-only positive/negative oracle fixtures."""
    roles = [C, 'Host'] + sorted(P._OBSERVER_ROLES - {C, 'Host'})
    pids = {name: 100 + i for i, name in enumerate(roles)}
    rows = {name: [] for name in roles}

    def emit(role, event, **detail):
        parent = 'Host' if role in ('Signer1', 'Signer2') else C
        parent_pid = 1 if role == C else pids[parent]
        record = dict(version=1, sequence=len(rows[role]) + 1, role=role, pid=pids[role],
            ppid=parent_pid, original_parent_pid=parent_pid, elapsed_ms=(len(rows[role]) + 1) * 10,
            event=event, detail=detail)
        rows[role].append(record)
        return record

    def observe(role, kind, **facts):
        return emit(role, 'Observation', observation=kind, facts=facts)

    for role in roles:
        emit(role, 'RetainedBindings', children=[dict(role=x, pid=pids[x]) for x in sorted(P._OBSERVER_CHILDREN[role])],
             startup_deadline_ms=30000, session_deadline_ms=300000)
    emit(C, 'Prepare', direction='Sent', original_ceiling_ms=120000)
    emit(W, 'Prepare', direction='Received', original_ceiling_ms=None)
    review = dict(presentation_digest=D, prepared_at_ms=1000000, expires_at_ms=1120000)
    emit(W, 'Review', direction='Sent', monotonic_deadline_ms=110000, **review)
    emit(C, 'Review', direction='Received', monotonic_deadline_ms=109999, **review)

    def snapshot(frame, *, cleared=False, acknowledged=False, focused=True, raw_blur=False):
        facts = dict(frame=frame, **{'pass': frame}, pixels_per_point=1.0,
            phase='Revoked' if cleared else ('Acknowledging' if acknowledged else 'Reading'),
            viewport=copy.deepcopy(RECT), presentation_digest=None if cleared else D,
            focused=focused, raw_blur=raw_blur, revoked=cleared, read_to_end=not cleared,
            continued=acknowledged, acknowledged=acknowledged,
            widgets=[] if cleared else [dict(widget='Review', rect=copy.deepcopy(RECT), enabled=True)])
        if acknowledged:
            facts['widgets'].append(dict(widget='Arm', rect=copy.deepcopy(RECT), enabled=True))
        return observe(C, 'WidgetSnapshot', **facts)

    source = snapshot(1)
    ready = dict(presentation_digest=D, effect_commitment=EFFECT, request_commitment=REQUEST,
        source_commitment='f' * 64, owner_certificate_digest=OWNER,
        expected_head_sequence=4, expected_head_digest='4' * 64, preparation_nonce=NONCE,
        accepted_at_ms=1001000, accepted_tls_expires_at_ms=1011000)
    if case == 'append':
        source = snapshot(2, acknowledged=True)
        emit(C, 'Arm', direction='Native', presentation_digest=D)
        emit(C, 'Arm', direction='Sent', presentation_digest=D)
        emit(W, 'Arm', direction='Received', presentation_digest=D)
        emit(W, 'Ready', direction='Sent', data=copy.deepcopy(ready), monotonic_deadline_ms=9000)
        emit(C, 'Ready', direction='Received', data=copy.deepcopy(ready), monotonic_deadline_ms=8999)
        emit(C, 'Admit', direction='Native', presentation_digest=D, effect_commitment=EFFECT)
        emit(C, 'Admit', direction='Sent', presentation_digest=D, effect_commitment=EFFECT)
        emit(W, 'Admit', direction='Received', presentation_digest=D, effect_commitment=EFFECT)
    if case == 'blur':
        observe(C, 'RawInterruption', blur=True, focused=False, escape=False, close=False)
    observe(C, 'PresentationCleared', presentation_digest=D, admitted=case == 'append')
    emit(C, 'Cancel', direction='Sent')
    emit(W, 'Cancel', direction='Received')
    observe(W, 'WorkerJoined', presentation_digest=D)
    if first_failure:
        data = dict(stage='TlsAccept', **{'class': 'Expired'})
        emit(W, 'FirstFailure', direction='Sent', data=copy.deepcopy(data))
        emit(C, 'FirstFailure', direction='Received', data=copy.deepcopy(data))
    outcome = dict(outcome='Committed' if case == 'append' else 'KnownNoEffect',
                   presentation_digest=D, effect_commitment=EFFECT if case == 'append' else None)
    if case == 'append': outcome.update(head_sequence=5, head_digest='5' * 64)
    emit(W, 'Outcome', direction='Sent', data=copy.deepcopy(outcome))
    emit(C, 'Outcome', direction='Received', data=copy.deepcopy(outcome))
    emit(W, 'Disposed', direction='Sent')
    emit(C, 'Disposed', direction='Received')
    clear = snapshot(3, cleared=True)
    for role in roles:
        for child in sorted(P._OBSERVER_CHILDREN[role]):
            emit(role, 'OwnedReap', child_role=child, child_pid=pids[child], exit_code=0, signal=None, forced=False)
    observe(C, 'DriverJoined', clean=True)
    for role in roles:
        emit(role, 'RoleFinished', exit_code=0)
        emit(role, 'EvidenceClosed', complete=True)
    records = [r for role in roles for r in rows[role]]
    original = dict(descriptor_digest='0' * 64, request_commitment=REQUEST, cutoff_ns=900000000001,
        account_id='9' * 64, operation_id='original-operation', expected_head=dict(sequence=4, digest='4' * 64),
        owner_certificate_digest=OWNER)
    audit = dict(result=dict(version=1, kind='pristine_delivery_originals_audit_v1',
        expectation='one_exact_append' if case == 'append' else 'pristine',
        original_account_histories=3, original_main_journals=3, target_original_prefix_events=4,
        target_current_events=5 if case == 'append' else 4, unchanged_non_target_histories=2,
        exact_retained_request_appends=int(case == 'append'), original_source_commitments_match=True,
        no_successor_effect=True), original=original, current=copy.deepcopy(original),
        drain=dict(root_pid=pids[C], exit_status=0, remaining_pids=[], remaining_process_groups=[], observed_ns=100),
        audited_ns=110)

    def capture(record, sequence, clock, input_sequence):
        snap = record['detail']['facts']
        return dict(snapshot_sequence=record['sequence'], frame=snap['frame'], **{'pass': snap['pass']},
            presentation_digest=snap['presentation_digest'], snapshot_read_ns=clock,
            requested_ns=clock+1, completed_ns=clock+2,
            request_receipt=receipt(sequence, sequence, sequence, input_sequence),
            observed_receipt=receipt(sequence, sequence+1, sequence+1, input_sequence),
            region={k: int(v) for k,v in RECT.items()},
            region_before_digest=('6' if record is source else '7') * 64,
            region_after_digest=('7' if record is source else '6') * 64)
    paint = dict(root_pid=pids[C], app_id='org.wholepact.CoordinatorDelivery',
        artifact_digest='8' * 64, original_artifact_digest='8' * 64,
        source=capture(source, 4, 10, 3), cleared=capture(clear, 8, 40, 6 if case == 'blur' else 5),
        action=receipt(5, 5, 5, 5), focus_out=receipt(5, 5, 5, 5) if case == 'blur' else None,
        refocus=receipt(6, 6, 6, 6) if case == 'blur' else None)
    owner = None if case != 'append' else dict(version=1, scope='synthetic-witness-one-append-only',
        outcome='Committed', original_monotonic_cutoff_ns=original['cutoff_ns'],
        preparation_nonce=NONCE, request_commitment=REQUEST, account_id=original['account_id'],
        operation_id=original['operation_id'], expected_head=copy.deepcopy(original['expected_head']),
        committed_head=dict(sequence=5, digest='5' * 64))
    return records, dict(root_pid=pids[C], root_status=0, audit=audit, paint=paint, owner_client=owner)


def find(records, event, role=C, direction=None):
    return next(r for r in records if r['role'] == role and r['event'] == event and
                (direction is None or r['detail'].get('direction') == direction))


def resequence(records):
    counts = {}
    for r in records:
        counts[r['role']] = counts.get(r['role'], 0) + 1
        r['sequence'] = counts[r['role']]
        r['elapsed_ms'] = r['sequence'] * 10


class Observer(unittest.TestCase):
    def reject(self, records, args, code=None, case='cancel'):
        with self.assertRaises(P.Rejected) as got:
            P.project_case(records, case, **args)
        if code: self.assertEqual(got.exception.code, code)
        P.validate_failure(got.exception.failure, 'fixture')
        self.assertLessEqual(len(json.dumps(got.exception.failure)), 1024)

    def test_all_three_pure_synthetic_cases(self):
        for case in P.CASES:
            records, args = fabricated(case)
            result = P.project_case(records, case, **args)
            self.assertEqual(set(result), P.FIXTURE_KEYS)
            self.assertEqual(result['native_admit_count'], int(case == 'append'))
            self.assertNotIn(D, json.dumps(result))
            self.assertNotIn('root_pid', result)

    def test_source_diagnostic_does_not_invent_effect(self):
        records, args = fabricated(first_failure=True)
        P.project_case(records, 'cancel', **args)
        self.assertEqual(P.delivery_first_failure(records), {'stage': 'TlsAccept', 'class': 'Expired'})

    def test_latest_partial_snapshot_returns_exact_root_record(self):
        records, args = fabricated()
        partial = [r for r in records if r['role'] != C or r['sequence'] <= 4]
        snapshot = P.latest_widget_snapshot(partial, root_pid=args['root_pid'])
        self.assertEqual(snapshot['detail']['facts']['presentation_digest'], D)
        snapshot['detail']['facts']['presentation_digest'] = None
        self.assertEqual(find(records, 'Observation')['detail']['facts']['presentation_digest'], D)
        with self.assertRaises(P.Rejected): P.latest_widget_snapshot(partial, root_pid=999)
        with self.assertRaises(P.Rejected): P.latest_widget_snapshot(records, root_pid=args['root_pid'])

    def test_exact_event_fields_and_unknown_role_direction(self):
        records, _ = fabricated('append')
        for record in records: P.validate_record(record)
        for mutate in (
            lambda r: r.update(extra='private'), lambda r: r.update(role='Signer'),
            lambda r: r['detail'].update(direction='Received'), lambda r: r.update(version=True),
            lambda r: r.update(pid=True), lambda r: r.update(sequence=0),
        ):
            record = copy.deepcopy(find(records, 'Arm', direction='Native'))
            mutate(record)
            with self.assertRaises(P.Rejected): P.validate_record(record)

    def test_finite_rectangles_scales_widget_identity_and_bounds(self):
        records, _ = fabricated()
        good = find(records, 'Observation')
        changes = [lambda s: s.update(pixels_per_point=True), lambda s: s.update(pixels_per_point=float('inf')),
            lambda s: s['viewport'].update(right=10**400), lambda s: s['viewport'].update(left=100),
            lambda s: s['widgets'].append(copy.deepcopy(s['widgets'][0])),
            lambda s: s['widgets'][0]['rect'].update(right=101), lambda s: s.update(focused=1),
            lambda s: s.update(phase='Approved'), lambda s: s.update(presentation_digest='A'*64)]
        for change in changes:
            bad = copy.deepcopy(good); change(bad['detail']['facts'])
            with self.assertRaises(P.Rejected): P.validate_record(bad)

    def test_json_files_duplicate_fields_and_filename_binding(self):
        records, _ = fabricated()
        files = {}
        for r in records: files.setdefault(str(r['pid'])+'.jsonl', b''); files[str(r['pid'])+'.jsonl'] += json.dumps(r).encode()+b'\n'
        parsed = P.load_observer_files(files)
        self.assertEqual(parsed, records)
        for bad in ({'999.jsonl': next(iter(files.values()))}, {'0100.jsonl': next(iter(files.values()))},
                    {'100.jsonl': b'{"version":1,"version":1}\n'}, {'100.jsonl': b'{}'},
                    {'100.jsonl': b' '*(256*1024)+b'\n'}, {'100.jsonl': b'\n'},
                    {'1'*5000+'.jsonl': b'{}\n'}):
            with self.assertRaises(P.Rejected): P.load_observer_files(bad)

    def test_local_sequences_times_and_graph_are_exact(self):
        for mutation, code in (
            (lambda rs: rs[1].update(sequence=3), 'record_sequence'),
            (lambda rs: rs[1].update(elapsed_ms=0), 'record_sequence'),
            (lambda rs: find(rs, 'RetainedBindings', W).update(original_parent_pid=999), 'record_parent'),
            (lambda rs: find(rs, 'RetainedBindings', W).update(ppid=1), 'record_parent'),
            (lambda rs: rs[0].update(original_parent_pid=2), 'record_parent'),
            (lambda rs: rs[0]['detail']['children'].pop(), 'record_graph'),
        ):
            records, args = fabricated(); mutation(records); self.reject(records, args, code)

    def test_all_roles_close_and_all_exclusive_reaps_succeed(self):
        for role, event, key, value, code in (
            (C, 'EvidenceClosed', 'complete', False, 'record_incomplete'),
            (W, 'RoleFinished', 'exit_code', 1, 'product_status'),
            (C, 'OwnedReap', 'forced', True, 'owned_reap'),
            (C, 'OwnedReap', 'child_pid', 999, 'owned_reap'),
        ):
            records, args = fabricated(); find(records, event, role)['detail'][key] = value
            self.reject(records, args, code)
        records, args = fabricated(); records.remove(find(records, 'EvidenceClosed', W)); self.reject(records, args, 'record_incomplete')
        records, args = fabricated(); args['root_status'] = 1; self.reject(records, args, 'product_status')

    def test_received_timestamp_need_not_follow_sent(self):
        records, args = fabricated()
        # Every W observation can be stamped after the C receive while its own
        # sequence remains monotone. This is permitted by actual post-send hooks.
        for r in records:
            if r['role'] == W: r['elapsed_ms'] += 1000
        P.project_case(records, 'cancel', **args)

    def test_cancel_send_may_observe_before_synchronous_clear(self):
        records, args = fabricated()
        cleared = next(r for r in records if P._is_observation(r, 'PresentationCleared'))
        cancel = find(records, 'Cancel'); a, b = records.index(cleared), records.index(cancel)
        records[a], records[b] = records[b], records[a]
        resequence(records)
        P.project_case(records, 'cancel', **args)

    def test_negative_rejects_any_native_arm_or_ready(self):
        records, args = fabricated()
        find(records, 'Cancel')['event'] = 'Arm'; find(records, 'Arm')['detail'].update(presentation_digest=D)
        self.reject(records, args)

    def test_missing_channel_receive_and_mismatched_payload(self):
        records, args = fabricated('append')
        find(records, 'Ready', C)['detail']['data']['source_commitment'] = '1'*64
        self.reject(records, args, 'ready_binding', 'append')
        records, args = fabricated('append')
        find(records, 'Admit', W)['detail']['effect_commitment'] = '2'*64
        self.reject(records, args, 'effect_binding', 'append')

    def test_worker_join_must_precede_outcome_and_disposal(self):
        records, args = fabricated()
        joined = next(r for r in records if P._is_observation(r, 'WorkerJoined'))
        outcome = find(records, 'Outcome', W)
        a,b=records.index(joined),records.index(outcome); records[a],records[b]=records[b],records[a]
        resequence(records); self.reject(records, args, 'worker_join')

    def test_unknown_and_cleanup_failure_never_pass_by_history(self):
        records, args = fabricated('append')
        for r in records:
            if r['event'] == 'Outcome':
                r['detail']['data'] = dict(outcome='Uncertain', presentation_digest=D, effect_commitment=EFFECT)
        self.reject(records, args, 'uncertain_effect', 'append')
        records, args = fabricated('append')
        next(r for r in records if P._is_observation(r, 'DriverJoined'))['detail']['facts']['clean'] = False
        self.reject(records, args, 'driver_join', 'append')

    def test_uncertain_has_actual_finite_first_failure_only(self):
        records, args = fabricated('append', first_failure=True)
        for r in records:
            if r['event'] == 'Outcome':
                r['detail']['data'] = dict(outcome='Uncertain', presentation_digest=D, effect_commitment=EFFECT)
        with self.assertRaises(P.Rejected) as got: P.project_case(records, 'append', **args)
        self.assertEqual(got.exception.failure['delivery_stage'], 'TlsAccept')
        unrelated = P.observer_failure(P.Rejected('owned_reap'), 'append', records=records)
        self.assertIsNone(unrelated['delivery_stage'])

    def test_blur_requires_real_false_event_refocus_and_no_reactivation(self):
        for mutation, code in (
            (lambda rs, a: find(rs, 'Observation')['detail']['facts'].update(revoked=True), 'source_prepare'),
            (lambda rs, a: a['paint'].update(refocus=None), 'refocus_missing'),
            (lambda rs, a: next(r for r in rs if P._is_observation(r, 'RawInterruption'))['detail']['facts'].update(blur=False), 'blur_missing'),
        ):
            records,args=fabricated('blur'); mutation(records,args); self.reject(records,args,code,'blur')
        records,args=fabricated('blur')
        snapshots=[r for r in records if P._is_observation(r,'WidgetSnapshot')]
        snapshots[-1]['detail']['facts'].update(revoked=False, phase='Selecting')
        self.reject(records,args,'reactivation','blur')

    def test_paint_requires_both_real_later_commit_frame_and_region_change(self):
        for key, value in (('commit', 4), ('frame', 4), ('input_sequence', 2), ('sequence', 3)):
            records,args=fabricated(); args['paint']['source']['observed_receipt'][key]=value
            self.reject(records,args,'source_paint')
        for name in ('source','cleared'):
            records,args=fabricated(); args['paint'][name]['region_after_digest']=args['paint'][name]['region_before_digest']
            self.reject(records,args,'source_paint')
        records,args=fabricated(); args['paint'].pop('cleared'); self.reject(records,args,'source_paint')
        records,args=fabricated(); args['paint']['app_id']='org.wholepact.CancelOnly'; self.reject(records,args,'display_binding')
        records,args=fabricated(); args['paint']['artifact_digest']='1'*64; self.reject(records,args,'display_binding')

    def test_audit_retains_original_request_cutoff_and_natural_drain(self):
        for mutation, code in (
            (lambda a: a['audit']['current'].update(cutoff_ns=900000000002), 'original_deadline'),
            (lambda a: a['audit']['current'].update(request_commitment='1'*64), 'original_request'),
            (lambda a: a['audit']['drain'].update(remaining_pids=[999]), 'adopted_child'),
            (lambda a: a['audit']['drain'].update(remaining_process_groups=[100]), 'adopted_child'),
            (lambda a: a['audit']['result'].update(original_account_histories=True), 'history_audit'),
            (lambda a: a['audit'].update(audited_ns=99), 'original_deadline'),
        ):
            records,args=fabricated(); mutation(args); self.reject(records,args,code)

    def test_owner_independent_response_not_coordinator_outcome(self):
        for mutation, code in (
            (lambda a: a.update(owner_client=None), 'owner_response'),
            (lambda a: a['owner_client'].update(preparation_nonce='1'*64), 'ready_binding'),
            (lambda a: a['owner_client']['committed_head'].update(digest='1'*64), 'effect_binding'),
            (lambda a: a['owner_client'].update(original_monotonic_cutoff_ns=1), 'original_deadline'),
            (lambda a: a['owner_client'].update(operation_id='different'), 'original_request'),
            (lambda a: a['owner_client'].update(outcome='Uncertain'), 'owner_response'),
        ):
            records,args=fabricated('append'); mutation(args); self.reject(records,args,code,'append')

    def test_record_count_and_extra_raw_fields_fail_closed(self):
        records,args=fabricated()
        with self.assertRaises(P.Rejected): P.validate_trace(records*50, root_pid=args['root_pid'], root_status=0)
        for name in ('audit','paint'):
            rs,kw=fabricated(); kw[name]['raw_child_text']='private'; self.reject(rs,kw)


    def test_all_aggregate_and_per_record_caps(self):
        records, args = fabricated()
        one = copy.deepcopy(find(records, 'RetainedBindings', W))
        with self.assertRaises(P.Rejected):
            P.validate_record(dict(one, sequence=513))
        with self.assertRaises(P.Rejected):
            P.load_observer_files({str(1000+i)+'.jsonl': b'{}\n' for i in range(33)})
        # Valid leaf JSON padded to the exact line and per-file limits; the
        # seventeenth bounded file crosses the independent total-byte ceiling.
        files = {}
        for i in range(17):
            item = dict(one, pid=1000+i)
            raw = json.dumps(item).encode()
            line = raw + b' '*(16384-len(raw)-1) + b'\n'
            files[str(1000+i)+'.jsonl'] = line*16
        with self.assertRaises(P.Rejected) as got: P.load_observer_files(files)
        self.assertEqual(got.exception.code, 'record_overflow')

    def test_snapshot_count_cap_and_strict_frame_order(self):
        records,args=fabricated()
        source = find(records, 'Observation')
        index = records.index(source)
        for n in range(256):
            item = copy.deepcopy(source)
            item['detail']['facts']['frame'] = n+10
            item['detail']['facts']['pass'] = n+10
            records.insert(index+1+n,item)
        resequence(records)
        self.reject(records,args,'record_overflow')
        records,args=fabricated()
        snaps=[r for r in records if P._is_observation(r,'WidgetSnapshot')]
        snaps[-1]['detail']['facts']['frame']=snaps[0]['detail']['facts']['frame']
        self.reject(records,args,'evidence_order')

    def test_duplicate_reap_and_role_reassignment_refused(self):
        records,args=fabricated()
        reaps=[r for r in records if r['role']==C and r['event']=='OwnedReap']
        reaps[1]['detail']=copy.deepcopy(reaps[0]['detail'])
        self.reject(records,args,'owned_reap')
        records,args=fabricated()
        for r in records:
            if r['role']==W: r['pid']=args['root_pid']
        self.reject(records,args,'record_graph')

    def test_real_protocol_deadlines_not_arbitrary_uints(self):
        records,args=fabricated('append')
        for r in records:
            if r['event']=='Ready': r['detail']['data']['accepted_tls_expires_at_ms']+=1
        self.reject(records,args,'record_deadline','append')
        records,args=fabricated()
        for r in records:
            if r['event']=='Review': r['detail']['expires_at_ms']+=1
        self.reject(records,args,'record_deadline')

    def test_closed_first_failure_and_unrelated_error_remain_separate(self):
        records,args=fabricated(first_failure=True)
        find(records,'FirstFailure',W)['detail']['data']['raw']='secret'
        self.reject(records,args,'record_schema')
        records,args=fabricated(first_failure=True)
        find(records,'FirstFailure',C)['detail']['data']['stage']='TlsRequest'
        self.reject(records,args,'ready_binding')
        self.assertEqual(P.observer_failure(Exception('raw secret'), 'cancel')['code'],'internal')


    def test_independent_deadline_samples_do_not_invent_wire_instant(self):
        records,args=fabricated('append')
        # Receiver local millisecond deadline may exceed the independently
        # rounded sender deadline while remaining under its own original bound.
        find(records,'Review',C)['detail']['monotonic_deadline_ms']=110001
        find(records,'Ready',C)['detail']['monotonic_deadline_ms']=9001
        P.project_case(records,'append',**args)

    def test_paint_region_is_actual_review_and_same_after_clear(self):
        for where,key,val in (('source','left',1),('cleared','bottom',99),('source','right',1281),
                              ('source','top',True)):
            records,args=fabricated();args['paint'][where]['region'][key]=val
            self.reject(records,args,'source_paint')
        records,args=fabricated()
        args['paint']['cleared']['region_before_digest']='3'*64
        self.reject(records,args,'source_paint')


    def test_positive_admit_precedes_clear_and_final_send_precedes_cancel(self):
        records,args=fabricated('append')
        clear=next(r for r in records if P._is_observation(r,'PresentationCleared'))
        records.remove(clear)
        records.insert(records.index(find(records,'Admit',direction='Native')),clear)
        resequence(records)
        self.reject(records,args,'native_admit','append')
        records,args=fabricated('append')
        final=find(records,'Admit',direction='Sent'); cancel=find(records,'Cancel')
        a,b=records.index(final),records.index(cancel)
        records[a],records[b]=records[b],records[a]
        resequence(records)
        self.reject(records,args,'evidence_order','append')

    def test_owner_failure_parser_preserves_every_finite_cause(self):
        found=set()
        for stage in P.OWNER_CLIENT_STAGES:
            for wrapper, errors in (('Authority',P.OWNER_CLIENT_ERRORS),
                                    ('Source',P.OWNER_CLIENT_ERRORS),('Io',P.OWNER_CLIENT_IO)):
                for error in errors:
                    raw=f'CI_UI_OWNER_CLIENT_FAILURE stage={stage} cause={wrapper}({error})'
                    code=P.parse_owner_client_failure(raw)
                    self.assertEqual(code,f'owner_client_{stage}_{wrapper}_{error}')
                    self.assertEqual(P.parse_owner_client_failure((raw+'\n').encode()),code)
                    P.failure('fixture','append',code,'append')
                    found.add(code)
            code=P.parse_owner_client_failure(f'CI_UI_OWNER_CLIENT_FAILURE stage={stage} cause=PredicateDenied')
            self.assertEqual(code,f'owner_client_{stage}_PredicateDenied');found.add(code)
        for error in P.OWNER_CLIENT_ERRORS:
            code=P.parse_owner_client_failure(f'CI_UI_OWNER_CLIENT_FAILURE stage=Prepare cause=Aborted({error})')
            self.assertEqual(code,f'owner_client_Prepare_Aborted_{error}');found.add(code)
        code=P.parse_owner_client_failure('CI_UI_OWNER_CLIENT_FAILURE stage=Prepare cause=NotListening')
        self.assertEqual(code,'owner_client_Prepare_NotListening');found.add(code)
        self.assertEqual(found,P.OWNER_CLIENT_CODES)
        self.assertTrue(found<=P.CODES)

    def test_owner_failure_parser_rejects_noncanonical_or_arbitrary_text(self):
        good='CI_UI_OWNER_CLIENT_FAILURE stage=ReadIo cause=Io(TimedOut)'
        bad=[None,1,True,good+' private',good+'\r\n',good+'\n\n',good+'\x00',
             ' '+good,good.replace(' cause=', '  cause='),good.replace('ReadIo','Unknown'),
             good.replace('Io(TimedOut)','Io(Unknown)'),good.replace('Io(TimedOut)','TimedOut'),
             good.replace('Io(TimedOut)','Authority(TimedOut)'),good.replace('ReadIo','Prepare'),
             good.replace('Io(TimedOut)','Source( Expired )'),good.replace('Io(TimedOut)','Io(TimedOut, path)'),
             'CI_UI_OWNER_CLIENT_FAILURE stage=Prepare cause=Aborted(Uncertain) suffix',
             'CI_UI_OWNER_CLIENT_FAILURE stage=Prepare cause=Authority(Expired)',
             'CI_UI_OWNER_CLIENT_FAILURE stage=ReadIo cause=NotListening',
             'CI_UI_OWNER_CLIENT_FAILURE stage=ReadIo cause=PredicateDenied()',
             b'CI_UI_OWNER_CLIENT_FAILURE stage=ReadIo cause=Io(\xff)',b'x'*257,
             'CI_UI_OWNER_CLIENT_FAILURE stage=ReadIo cause=Source(é)']
        for line in bad:
            with self.assertRaises(P.Rejected) as got: P.parse_owner_client_failure(line)
            self.assertEqual(got.exception.code,'owner_response')

    def test_owner_failure_static_enums_equal_actual_rust_source(self):
        import re
        root=pathlib.Path(__file__).parents[2]
        transport=(root/'crates/wholepact-authority/src/transport/durable_delivery_admission_v3.rs').read_text()
        authority=(root/'crates/wholepact-authority/src/lib.rs').read_text()
        def variants(source,name):
            body=source.split('pub enum '+name+' {',1)[1].split('}',1)[0]
            return frozenset(re.findall(r'^    ([A-Z][A-Za-z0-9_]*)\s*,',body,re.M))
        self.assertEqual(P.OWNER_CLIENT_STAGES,variants(transport,'AdmissionFailureStageV3'))
        self.assertEqual(P.OWNER_CLIENT_IO,variants(transport,'AdmissionIoKindV3'))
        self.assertEqual(P.OWNER_CLIENT_ERRORS,variants(authority,'AuthorityError'))
        self.assertEqual(P.OWNER_CLIENT_ERRORS,P.DELIVERY_CLASSES)
        cause=transport.split('pub enum AdmissionFailureCauseV3 {',1)[1].split('}',1)[0]
        self.assertEqual(frozenset(re.findall(r'^    ([A-Z][A-Za-z0-9_]*)',cause,re.M)),
                         frozenset(('Authority','Source','Io','PredicateDenied')))
        prepare=transport.split('pub enum PrepareDurableAdmissionErrorV3 {',1)[1].split('}',1)[0]
        self.assertEqual(frozenset(re.findall(r'^    ([A-Z][A-Za-z0-9_]*)',prepare,re.M)),
                         frozenset(('NotListening','Aborted')))


if __name__ == '__main__': unittest.main()
