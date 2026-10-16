#!/usr/bin/env python3
"""Synthetic local API acceptance. Starts its own process; never uses a network wallet."""
import datetime, hashlib, json, pathlib, subprocess, tempfile, time, urllib.request, urllib.error, uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:4318'
ORIGIN = 'http://127.0.0.1:4319'
checks = []

def request(path, method='GET', payload=None, headers=None):
    h = {'Origin': ORIGIN, **(headers or {})}
    data = None if payload is None else json.dumps(payload).encode()
    if data is not None:
        h['Content-Type'] = 'application/json'
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read()
    return response.status, json.loads(body) if body else None, dict(response.headers)

def check(name, condition):
    assert condition, name
    checks.append({'name': name, 'result': 'PASS'})

with tempfile.TemporaryDirectory(prefix='wholepact-api-') as tmp:
    with open(pathlib.Path(tmp) / 'service.log', 'wb') as log:
        process = subprocess.Popen([str(ROOT/'target/debug/wholepact-service'), '--development-fixture', '--database', str(pathlib.Path(tmp)/'synthetic.sqlite')], stdout=log, stderr=log)
        try:
            for _ in range(100):
                try:
                    status, _, _ = request('/v1/health')
                    break
                except (urllib.error.URLError, ConnectionError):
                    if process.poll() is not None:
                        raise RuntimeError('Service exited before readiness')
                    time.sleep(.1)
            else:
                raise RuntimeError('Service readiness timed out')
            check('unauthenticated health denies useful data', status == 401)
            status, session, _ = request('/v1/session', headers={'Authorization':'Bearer wholepact-development-only-not-a-secret'})
            check('ephemeral development session established', status == 200 and bool(session['session_token']))
            auth = {'Authorization':'Bearer '+session['session_token'], 'X-Wholepact-CSRF':session['csrf_token']}
            status, cap, _ = request('/v1/capabilities', headers=auth)
            check('capabilities accessible', status == 200)
            status, _, _ = request('/v1/agreements', headers={**auth, 'Origin':'https://hostile.example'})
            check('hostile origin denied', status == 403)
            draft = json.loads((ROOT/'crates/wholepact-core/tests/fixtures/agreement.json').read_text())
            unique = uuid.uuid4().hex
            draft['agreement_id'] = 'root-'+unique
            draft['obligation_id'] = 'obligation-'+unique
            command = {**auth, 'Idempotency-Key':'create-'+unique}
            status, first, _ = request('/v1/agreements', 'POST', draft, command)
            check('agreement persisted through real API', status == 200 and first['revision'] == 1)
            status, replay, headers = request('/v1/agreements', 'POST', draft, command)
            check('same command replays unchanged', status == 200 and replay == first)
            changed = {**draft, 'purpose':'Changed payload under same command key'}
            status, _, _ = request('/v1/agreements', 'POST', changed, command)
            check('changed idempotency payload conflicts', status == 409)
            intent = {'intent_id':'intent-'+unique, 'agreement_id':draft['agreement_id'], 'participant_id':'synthetic-owner', 'desired_contribution':'1000000000','maximum_net_debit':'1000100000','fee_cap':'100000','conditions':[],'valid_until':None,'status':'active'}
            command2 = {**auth, 'Idempotency-Key':'intent-'+unique, 'If-Match':'"1"'}
            status, view, _ = request('/v1/agreements/'+draft['agreement_id']+'/intents','POST',intent,command2)
            check('first intent uses actual stored revision', status == 200 and view['revision'] == 2)
            status, _, _ = request('/v1/agreements/'+draft['agreement_id']+'/cancellation-requests','POST',{}, {**auth,'Idempotency-Key':'stale-'+unique,'If-Match':'"1"'})
            check('stale revision conflicts', status == 409)
            status, final, _ = request('/v1/agreements/'+draft['agreement_id'],headers=auth)
            check('read preserves committed revision', status == 200 and final['revision'] == 2)
            status, _, _ = request('/v1/session/end','POST',{},auth)
            check('session ends', status == 200)
            status, _, _ = request('/v1/agreements',headers=auth)
            check('ended session denied', status == 401)
        finally:
            process.terminate()
            process.wait(timeout=10)

out = ROOT/'reports/local-api-acceptance.json'
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps({'scope':'synthetic-local-metadata-api-no-signing-no-chain', 'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'binary_sha256':hashlib.sha256((ROOT/'target/debug/wholepact-service').read_bytes()).hexdigest(), 'command':'python scripts/check-local-api.py', 'checks':checks},indent=2)+'\n')
print(json.dumps({'passed':len(checks),'report':str(out)}))
