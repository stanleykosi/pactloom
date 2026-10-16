#!/usr/bin/env python3
"""Actual foreground terminal source qualification using disposable synthetic profiles.
No user profiles, production accounts, real funds, networks or services are touched.
This deliberately uses a PTY to test the source, NOT to claim trusted user-origin
attestation. Never save raw transcripts: they may contain random test credentials.
"""
import hashlib, json, os, pathlib, pty, re, secrets, select, signal, socket, sys, tempfile, threading, time, urllib.request, urllib.error

BINARY = pathlib.Path(sys.argv[1]).resolve()
REPO = pathlib.Path(__file__).resolve().parents[3]
class Native:
    def __init__(self, *args):
        self.pid,self.fd=pty.fork()
        if self.pid==0:
            os.execv(str(BINARY),[str(BINARY),*map(str,args)])
        self.buffer=b''
    def send(self,text): os.write(self.fd,(str(text)+'\n').encode())
    def until(self,pattern,timeout=90,approve=False):
        deadline=time.monotonic()+timeout
        rex=re.compile(pattern,re.S)
        output=b''
        while time.monotonic()<deadline:
            text=self.buffer.decode(errors='replace')
            match=rex.search(text)
            if match:
                output+=self.buffer[:match.end()];self.buffer=self.buffer[match.end():]
                return output.decode(errors='replace')
            if approve:
                challenge=re.search(r'Type (APPROVE [0-9a-f]{16}) to approve this exact operation, or anything else to reject: ',text)
                if challenge:
                    output+=self.buffer[:challenge.end()];self.buffer=self.buffer[challenge.end():];self.send(challenge.group(1));continue
            if select.select([self.fd],[],[],.1)[0]:
                try: block=os.read(self.fd,65536)
                except OSError: block=b''
                if not block: break
                self.buffer+=block
        raise AssertionError('Native process did not reach expected state: '+pattern)
    def approve_once(self):
        text=self.until(r'Type (APPROVE [0-9a-f]{16}) to approve this exact operation, or anything else to reject: ')
        self.send(re.search(r'APPROVE [0-9a-f]{16}',text).group(0))
    def finish(self):
        _,status=os.waitpid(self.pid,0);os.close(self.fd)
        assert os.waitstatus_to_exitcode(status)==0
    def close(self):
        try: os.kill(self.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        try: os.waitpid(self.pid,0)
        except ChildProcessError: pass
        try: os.close(self.fd)
        except OSError: pass

def init(profile,password):
    p=Native('init','--profile',profile)
    try:
        p.until(r'New storage passphrase .*: ',approve=True);p.send(password)
        p.until(r'Repeat passphrase: ');p.send(password)
        p.until(r'profile initialized and locked');p.finish()
    except: p.close();raise

def unlock(profile,password):
    p=Native('unlock','--profile',profile);p.until(r'Storage passphrase: ');p.send(password);p.until(r'wholepact-native> ');return p

def command(p,name,answers=(),approve=True):
    p.send(name)
    for pattern,answer in answers:
        p.until(pattern,approve=approve);p.send(answer)
    return p.until(r'wholepact-native> ',approve=approve)

def lock(p):p.send('lock');p.until(r'Locked\.');p.finish()
def enroll(p,root,name):
    return command(p,'enroll',[(r'Local application principal ID: ',name),(r'Scope choice:.*: ','ALL'),(r'Grant READ only.*\? ','PREPARE'),(r'New private bootstrap credential file.*: ',root/(name+'.token'))])
def json_file(root,name,data):p=root/name;p.write_text(json.dumps(data));p.chmod(0o600);return p

def serve_check(p,token,old=None,owned_ids=None,pending_invitation=None):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    p.send('serve');p.until(r'Explicit loopback service port .*: ');p.send(port);p.approve_once()
    def get(credential,path="/v1/session"):
        headers={'Authorization':'Bearer '+credential} if credential else {}
        request=urllib.request.Request(f'http://127.0.0.1:{port}{path}',headers=headers)
        try:
            with urllib.request.urlopen(request,timeout=2) as response:return response.status,response.read()
        except urllib.error.HTTPError as error:return error.code,error.read()
    deadline=time.monotonic()+30
    while True:
        try: status,data=get(token);break
        except (OSError,urllib.error.URLError):
            if time.monotonic()>deadline:raise AssertionError('Foreground service failed to bind')
            time.sleep(.05)
    assert status==200,(status,data)
    session=json.loads(data)
    assert get(session["session_token"],"/v1/capabilities")[0]==200
    assert get(None)[0]==401
    if old is not None:assert get(old)[0]==401
    assert session['owned_agreements_included'] is True
    assert session['owned_agreements_includes_future'] is True
    assert session['agreement_ids_semantics']=='additional_shared_agreements'
    if owned_ids:
        status,data=get(session['session_token'],'/v1/agreements')
        assert status==200
        assert set(owned_ids).issubset({r['agreement']['agreement_id'] for r in json.loads(data)})
        assert session['all_agreements'] is False
    pending=None
    if pending_invitation:
        def blocked_read():
            try:get(session['session_token'],'/v1/invitations/'+pending_invitation)
            except (OSError,urllib.error.URLError):pass
        pending=threading.Thread(target=blocked_read);pending.start()
        p.until(r'Type (APPROVE [0-9a-f]{16}) to approve this exact operation, or anything else to reject: ')
    os.kill(p.pid,signal.SIGINT)
    if pending:
        time.sleep(.3)
        while select.select([p.fd],[],[],0)[0]:p.buffer+=os.read(p.fd,65536)
        assert b'wholepact-native> ' not in p.buffer,'Shell resumed before blocking native consent drained'
        p.send('REJECT')
    p.until(r'wholepact-native> ')
    if pending:pending.join(timeout=5);assert not pending.is_alive()


def main():
    results=[]
    with tempfile.TemporaryDirectory(prefix='wholepact-native-synthetic-') as d:
        root=pathlib.Path(d);root.chmod(0o700);password=secrets.token_hex(24)
        sender=root/'sender';receiver=root/'receiver';init(sender,password);init(receiver,password)
        results.append('explicit_init_random_storage_only_profiles')
        p=unlock(sender,password);q=unlock(receiver,password)
        try:
            output=command(p,'records');assert 'not explicitly approved' in output
            enroll(p,root,'synthetic-organizer');enroll(q,root,'synthetic-recipient')
            assert (root/'synthetic-organizer.token').stat().st_mode&0o077==0
            pub=command(p,'public-key');sender_key=re.search(r'public key: ([0-9a-f]{64})',pub).group(1);sender_fp=re.search(r'Fingerprint: ([0-9a-f]{64})',pub).group(1)
            pub=command(q,'public-key');receiver_key=re.search(r'public key: ([0-9a-f]{64})',pub).group(1)
            draft=json.loads((REPO/'crates/wholepact-core/tests/fixtures/agreement.json').read_text());draft['purpose']='SYNTHETIC NATIVE HOST PRIVATE CANARY'
            draftfile=json_file(root,'draft.json',draft)
            output=command(p,'create',[(r'Native draft JSON file: ',draftfile)]);assert 'agreement-example-01' in output
            output=command(p,'agreement',[(r'Agreement ID: ',draft['agreement_id'])]);digest=re.search(r'Invitation agreement digest: ([0-9a-f]{64})',output).group(1)
            context={'network_profile_id':draft['network_profile_id'],'agreement_id':draft['agreement_id'],'proposal_id':'native-invitation','proposal_revision':1,'sender_id':draft['organizer_identity'],'recipient_id':'synthetic-participant','artifact_kind':'invitation'}
            contextfile=json_file(root,'context.json',context)
            command(p,'pin',[(r'Exact expected context JSON file: ',contextfile),(r'Direction .*: ','outgoing'),(r'Independently verified peer public key .*: ',receiver_key)])
            command(q,'pin',[(r'Exact expected context JSON file: ',contextfile),(r'Direction .*: ','incoming'),(r'Independently verified peer public key .*: ',sender_key)])
            def stamp(delta):return time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+delta))
            invite={'expected_agreement_revision':1,'context':context,'order':{'message_id':secrets.token_hex(16),'sequence':1,'issued_at':stamp(-1),'expires_at':stamp(15)},'purpose':'Private invitation synthetic source test','persistence_warning':'Recipient may retain this selected disclosure.','invitation':{'schema_version':1,'invitation_id':secrets.token_hex(16),'organizer_key_fingerprint':sender_fp,'invited_participant_id':context['recipient_id'],'agreement_manifest_digest':digest,'offered_roles':['contributor'],'purpose':draft['purpose'],'recipient_summary':'Synthetic receiving address remains unverified.','fee_summary':'No fee authorization.','visibility_summary':'Read-only synthetic invitation.','coordination_deadline':stamp(1200)}}
            expiry_deadline=time.time()+16
            invitefile=json_file(root,'invitation.json',invite)
            output=command(p,'prepare-invitation',[(r'Exact invitation export JSON file: ',invitefile)]);handle=re.search(r'"handle": "([^"]+)"',output).group(1)
            pairs=[(r'Agreement ID: ',draft['agreement_id']),(r'Opaque artifact handle: ',handle)]
            command(p,'seal',pairs)
            export=root/'invitation.wp';command(p,'export',pairs+[(r'New local encrypted export path: ',export)])
            before=export.read_bytes();assert draft['purpose'].encode() not in before
            again=root/'invitation-again.wp';command(p,'export',pairs+[(r'New local encrypted export path: ',again)]);assert before==again.read_bytes()
            output=command(q,'intake',[(r'Independently expected context JSON file: ',contextfile),(r'Encrypted transport file: ',export)]);incoming=re.search(r'"handle": "([^"]+)"',output).group(1)
            output=command(q,'invitation',[(r'Agreement ID: ',draft['agreement_id']),(r'Opaque artifact handle: ',incoming)]);assert draft['purpose'] in output and '"wallet_control_verified": false' in output
            results.append('native_exact_consent_transport_prepare_seal_idempotent_export_authenticated_intake_readonly_invitation')
            old_token=(root/'synthetic-organizer.token').read_text();serve_check(p,old_token)
            results.append('actual_authenticated_foreground_http_start_stop')
            serve_check(q,(root/'synthetic-recipient.token').read_text(),pending_invitation=incoming)
            results.append('shutdown_waits_for_inflight_native_consent_before_shell_backup')
            time.sleep(max(0,expiry_deadline-time.time()))
            output=command(q,'recover',[(r'Original exact context JSON file: ',contextfile),(r'Original retained sequence: ',1)])
            assert '"currently_valid": false' in output and '"historical": true' in output
            incoming=re.search(r'"handle": "([^"]+)"',output).group(1)
            output=command(q,'invitation',[(r'Agreement ID: ',draft['agreement_id']),(r'Opaque artifact handle: ',incoming)])
            assert draft['purpose'] in output and '"currently_valid": false' in output
            output=command(q,'intake',[(r'Independently expected context JSON file: ',contextfile),(r'Encrypted transport file: ',export)])
            assert 'not explicitly approved' in output
            results.append('expired_retained_invitation_remains_readable_without_new_intake_authority')
            backup=root/'backup';backup_password=secrets.token_hex(24)
            output=command(p,'backup',[(r'NEW private backup directory .*: ',backup),(r'Backup recovery passphrase: ',backup_password),(r'Repeat backup recovery passphrase: ',backup_password)]);assert '"writer_freshness_established": false' in output
            assert (backup/'COMPLETE').exists();results.append('whole_profile_encrypted_backup_verified')
            command(q,'revoke');output=command(q,'invitation',[(r'Agreement ID: ',draft['agreement_id']),(r'Opaque artifact handle: ',incoming)]);assert 'not explicitly approved' in output
            lock(q);q=None;lock(p);p=None
            p=unlock(sender,password)
            second_token=root/'new-session.token'
            output=command(p,'enroll',[(r'Local application principal ID: ','synthetic-organizer'),(r'Scope choice:.*: ','OWNED'),(r'Additional shared agreement IDs.*: ',''),(r'Grant READ only.*\? ','READ'),(r'New private bootstrap credential file.*: ',second_token)])
            assert 'All existing AND future agreements owned by this principal are included.' in output
            newer=dict(draft);newer['agreement_id']='future-owned-synthetic';newer['obligation_id']='future-obligation-synthetic'
            newerfile=json_file(root,'future-draft.json',newer)
            command(p,'create',[(r'Native draft JSON file: ',newerfile)])
            command(p,'pin',[(r'Exact expected context JSON file: ',contextfile),(r'Direction .*: ','outgoing'),(r'Independently verified peer public key .*: ',receiver_key)])
            tampered=json.loads(json.dumps(invite));tampered['invitation']['purpose']='SUBSTITUTED SYNTHETIC PRIVATE PREVIEW'
            tamperedfile=json_file(root,'tampered-original.json',tampered)
            output=command(p,'recover-export',[(r'Original exact invitation export JSON file: ',tamperedfile)])
            assert 'not explicitly approved' in output
            output=command(p,'recover-export',[(r'Original exact invitation export JSON file: ',invitefile)])
            assert '"historical": true' in output and '"currently_valid": false' in output
            restored_handle=re.search(r'"handle": "([^"]+)"',output).group(1)
            recovered_pairs=[(r'Agreement ID: ',draft['agreement_id']),(r'Opaque artifact handle: ',restored_handle)]
            output=command(p,'seal',recovered_pairs);assert 'not explicitly approved' in output
            recovered_export=root/'recovered-committed.wp'
            command(p,'export',recovered_pairs+[(r'New local encrypted export path: ',recovered_export)])
            assert recovered_export.read_bytes()==before
            results.append('restart_recovers_exact_expired_committed_outgoing_bytes_without_reseal')
            new_token=second_token.read_text();assert new_token!=old_token
            serve_check(p,new_token,old_token,owned_ids=[draft['agreement_id'],newer['agreement_id']]);lock(p);p=None
            results.append('fresh_enrollment_rejects_previous_credential')
            results.append('explicit_ownerwide_grant_includes_existing_and_future_owned_agreements')
            restored=root/'restored';r=Native('restore','--backup',backup,'--destination',restored,'--test-only')
            r.until(r'Backup recovery passphrase: ');r.send(backup_password);r.until(r'New restored-profile passphrase: ');r.send(password);r.until(r'Repeat new passphrase: ');r.send(password);r.until(r'Restored history is quarantined\.',approve=True);r.finish()
            h=Native('history','--profile',restored,'--backup',backup);h.until(r'Restored profile passphrase: ');h.send(password);h.until(r'Original backup recovery passphrase: ');h.send(backup_password);h.until(r'Exact historical agreement ID: ');h.send(draft['agreement_id']);history=h.until(r'Historical read only\.',approve=True);assert '"authorization_exposure": "unknown"' in history and draft['purpose'] in history;h.finish()
            results.append('test_restore_quarantined_native_exact_history_read')
            for profile in [sender,receiver,restored]:
                for path in profile.glob('*.sqlite'):
                    data=path.read_bytes();assert not data.startswith(b'SQLite format 3\x00');assert draft['purpose'].encode() not in data
            results.append('encrypted_files_no_plaintext_private_canary')
        finally:
            if p:p.close()
            if q:q.close()
    print(json.dumps({'qualification':'synthetic disposable PTY source only; no real-user attestation or financial acceptance','passed':results},indent=2))
if __name__=='__main__':main()
