#!/usr/bin/env python3
"""Real native command/controller qualification over isolated synthetic records.
The fixture initializer exists only in the Rust test executable. All commands,
including first preview/stage and restarted write, use the shipped binary. No raw PTY transcripts or credentials are saved.
"""
import json, os, pathlib, re, secrets, signal, socket, sys, tempfile, time, urllib.error, urllib.request
import terminal_flow as base

BINARY=pathlib.Path(sys.argv[1]).resolve()
FIXTURE=pathlib.Path(sys.argv[2]).resolve()
AGREEMENT='synthetic-receipt-agreement'
RECORD='synthetic-private-record'
OWNER='synthetic-receipt-owner'

def enroll(p,root,filename,owner=OWNER):
    return base.command(p,'enroll',[(r'Local application principal ID: ',owner),(r'Scope choice:.*: ','ALL'),(r'Grant READ only.*\? ','READ'),(r'New private bootstrap credential file.*: ',root/filename)])

def request(p,name,answers,reject_export=False):
    p.send(name)
    for prompt,answer in answers:
        p.until(prompt,approve=True);p.send(answer)
    if reject_export:
        output=p.until(r'SEPARATE SELECTIVE RECEIPT CONSENT',approve=True)
        output+=p.until(r'Type APPROVE [0-9a-f]{16} to approve this exact operation, or anything else to reject: ')
        p.send('REJECT SEPARATE EXPORT')
        return output+p.until(r'wholepact-native> ',approve=True)
    return p.until(r'wholepact-native> ',approve=True)

def stage(p,root,export,revision,target,reject=False):
    f=base.json_file(root,export+'-stage.json',{'record_id':RECORD,'expected_record_revision':1,'preview_id':'amount-only-preview','export_id':export})
    return request(p,'receipt-stage',[(r'Agreement ID: ',AGREEMENT),(r'Original stage agreement revision: ',revision),(r'Original stage command idempotency key .*: ','stage-'+export),(r'Exact staged receipt export request JSON file: ',f),(r'Exact private PLAINTEXT receipt destination: ',target)],reject)

def write(p,root,export,target,reject=False):
    f=base.json_file(root,export+'-write.json',{'record_id':RECORD,'export_id':export})
    return request(p,'receipt-write',[(r'Agreement ID: ',AGREEMENT),(r'Original write attempt idempotency key .*: ','write-'+export),(r'Exact retained receipt write request JSON file: ',f),(r'Original exact private PLAINTEXT receipt destination: ',target)],reject)

def status(p,export):
    return base.command(p,'receipt-status',[(r'Agreement ID: ',AGREEMENT),(r'Existing record ID: ',RECORD),(r'Original export ID: ',export)])

def revision(output):
    match=re.search(r'"agreement_revision": (\d+)',output)
    assert match,'Expected safe agreement revision metadata'
    return int(match.group(1))

def privacy_http(p,token,forbidden):
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    p.send('serve');p.until(r'Explicit loopback service port .*: ');p.send(port);p.approve_once()
    def get(path,credential):
        req=urllib.request.Request(f'http://127.0.0.1:{port}{path}',headers={'Authorization':'Bearer '+credential})
        try:
            with urllib.request.urlopen(req,timeout=3) as response:return response.status,response.read()
        except urllib.error.HTTPError as e:return e.code,e.read()
    deadline=time.monotonic()+30
    while True:
        try:code,data=get('/v1/session',token);break
        except (OSError,urllib.error.URLError):
            assert time.monotonic()<deadline;time.sleep(.05)
    assert code==200
    session=json.loads(data)['session_token']
    for path in ['/v1/agreements','/v1/agreements/'+AGREEMENT,'/v1/events?format=json']:
        code,data=get(path,session);assert code==200
        for secret in forbidden:assert secret.encode() not in data, 'Private category '+str(forbidden.index(secret))+' leaked through '+path
        if path=='/v1/events?format=json':
            for event in json.loads(data):
                operation=event.get('operation_id')
                if operation:
                    code,data=get('/v1/operations/'+operation,session);assert code==200
                    for secret in forbidden:assert secret.encode() not in data
    os.kill(p.pid,signal.SIGINT);p.until(r'wholepact-native> ')

def main():
    passed=[];p=None
    with tempfile.TemporaryDirectory(prefix='wholepact-native-receipt-synthetic-') as directory:
        root=pathlib.Path(directory);root.chmod(0o700);profile=root/'profile';password=secrets.token_hex(24)
        base.BINARY=FIXTURE
        p=base.Native('--ignored','--exact','host::receipt_fixture::native_receipt_fixture_session','--nocapture')
        try:
            p.until(r'Disposable synthetic profile root: ');p.send(profile)
            p.until(r'Synthetic storage passphrase: ');p.send(password)
            p.until(r'Synthetic fixture initialized and locked\.');p.finish();p=None
            base.BINARY=BINARY;p=base.unlock(profile,password)
            enroll(p,root,'initial.token')
            output=base.command(p,'records');assert RECORD in output
            selected={'record_id':RECORD,'expected_record_revision':1,'preview_id':'amount-only-preview','selection':{'fields':['recipient_amount'],'payment_recipient_id':'recipient-example','destination':{'recipient_id':'synthetic-private-reviewer','destination':'synthetic local handoff only','audience':'named_private_recipient'},'purpose':'Only the synthetic selected amount','persistence':'The recipient may retain this selected plaintext file'},'method':{'kind':'private_receipt'}}
            f=base.json_file(root,'preview.json',selected)
            output=base.command(p,'receipt-preview',[(r'Agreement ID: ',AGREEMENT),(r'Current agreement revision: ',5),(r'Original preview command idempotency key .*: ','original-selected-preview'),(r'Selected receipt preview request JSON file: ',f)])
            rev=revision(output)
            output=base.command(p,'receipt-preview-read',[(r'Agreement ID: ',AGREEMENT),(r'Existing record ID: ',RECORD),(r'Original preview ID: ','amount-only-preview')]);assert 'recipient_amount' in output
            passed.append('existing_owned_record_exact_selected_preview_without_export')
            target=root/'selected-private-receipt.json'
            for forbidden in [profile/'selected.json',profile/'coordination.sqlite-journal']:
                output=stage(p,root,'first-export',rev,forbidden)
                assert 'DISCLOSURE_TARGET_PROTECTED_PROFILE_OR_UNSAFE' in output
                assert 'SEPARATE SELECTIVE RECEIPT CONSENT' not in output and not forbidden.exists()
            passed.append('active_profile_and_sqlite_sidecar_targets_rejected_before_consent_or_stage')
            output=stage(p,root,'first-export',rev,target,True);assert 'DISCLOSURE_CONSENT_DENIED' in output and not target.exists()
            output=stage(p,root,'first-export',rev,target);assert 'staged_no_file_effect' in output and not target.exists()
            original_ref=re.search(r'Consent reference: (native-receipt-[0-9a-f]+)',output).group(1)
            stagedrev=revision(output)
            output=stage(p,root,'first-export',rev,target);assert revision(output)==stagedrev and original_ref in output
            passed.append('separate_export_denial_then_durable_stage_exact_idempotency')
            privacy_http(p,(root/'initial.token').read_text(),[str(target),original_ref,'PRIVATE-SYNTHETIC','native_receipt_consent'])
            passed.append('all_scope_http_metadata_excludes_native_consent_and_private_record_payload')
            base.lock(p);p=None
            base.BINARY=BINARY;p=base.unlock(profile,password);enroll(p,root,'restart.token')
            output=write(p,root,'first-export',profile/'selected.json')
            assert 'DISCLOSURE_TARGET_PROTECTED_PROFILE_OR_UNSAFE' in output and 'SEPARATE SELECTIVE RECEIPT CONSENT' not in output
            output=write(p,root,'first-export',target,True);assert original_ref in output and 'DISCLOSURE_CONSENT_DENIED' in output and not target.exists()
            alternative=root/'unselected.json';output=write(p,root,'first-export',alternative);assert ('DISCLOSURE_INTENT_MISMATCH' in output or 'DISCLOSURE_CONSENT_DENIED' in output) and not alternative.exists()
            output=write(p,root,'first-export',target);assert original_ref in output and 'local_file_written_historical' in output and '"attempts": 1' in output
            exact=target.read_bytes();receipt=json.loads(exact)
            assert receipt['facts']==[{'field':'recipient_amount','value':'1000'}],receipt['facts']
            assert target.stat().st_mode&0o077==0
            for private in [RECORD,AGREEMENT,'synthetic-account-alice','PRIVATE-SYNTHETIC',original_ref,'03'*32]:assert private.encode() not in exact
            passed.append('shipped_binary_restart_fresh_exact_consent_original_reference_selected_plaintext_write')
            output=write(p,root,'first-export',target);assert '"attempts": 1' in output and target.read_bytes()==exact
            target.unlink() # disposable generated output, never a user file
            output=write(p,root,'first-export',target);assert 'local_file_written_historical' in output and not target.exists()
            output=status(p,'first-export');assert 'local_file_written_historical' in output and str(target) not in output and original_ref not in output
            current=revision(output)
            passed.append('exact_retry_and_historical_completion_never_recreates_deleted_copy')
            partial=root/'partial-selected-receipt.json'
            output=stage(p,root,'second-export',current,partial);assert 'staged_no_file_effect' in output
            partial.write_bytes(b'SYNTHETIC PARTIAL FILE');partial.chmod(0o600)
            output=write(p,root,'second-export',partial);assert 'DISCLOSURE_FILE_CONFLICT' in output and partial.read_bytes()==b'SYNTHETIC PARTIAL FILE'
            output=status(p,'second-export');assert 'file_outcome_unknown' in output
            partial.unlink() # remove only this test's deliberate conflicting generated artifact
            output=write(p,root,'second-export',partial);assert 'local_file_written_historical' in output and '"attempts": 1' in output and partial.read_bytes()==exact
            passed.append('specific_partial_conflict_preserves_bytes_status_unknown_same_attempt_recovers')
            backup=root/'receipt-covered-backup';recovery_password=secrets.token_hex(24)
            output=base.command(p,'backup',[(r'NEW private backup directory .*: ',backup),(r'Backup recovery passphrase: ',recovery_password),(r'Repeat backup recovery passphrase: ',recovery_password)])
            assert (backup/'COMPLETE').exists() and '"writer_freshness_established": false' in output
            passed.append('profile_remains_unlockable_and_full_backup_covers_encrypted_consent_aggregate')
            base.lock(p);p=None
            p=base.unlock(profile,password);enroll(p,root,'unrelated.token','synthetic-unrelated-principal')
            output=status(p,'first-export');assert 'RECORD_ACCESS_DENIED' in output or 'NOT_FOUND' in output or 'PERMISSION_DENIED' in output
            passed.append('all_scope_unrelated_principal_cannot_disclose_owned_record')
            base.lock(p);p=None
            for file in profile.iterdir():
                if file.is_file():
                    encrypted=file.read_bytes()
                    for private in [str(target),original_ref,'PRIVATE-SYNTHETIC']:
                        assert private.encode() not in encrypted,'Private export consent leaked at rest'
            passed.append('native_original_consent_and_record_encrypted_at_rest')
        finally:
            if p:p.close()
    print(json.dumps({'synthetic_only':True,'real_user_setup':False,'production_fixture_initializer':False,'passed':passed,'count':len(passed)},indent=2))
if __name__=='__main__':main()
