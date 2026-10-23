#!/usr/bin/env python3
"""Private inert full-fixture reader; never prepares/adopts a financial grant."""
import importlib.util
import json
import os
import pathlib
import stat
import sys
import time

ROOT=pathlib.Path(__file__).parent
_spec=importlib.util.spec_from_file_location('ci_financial_contract',ROOT/'ci-financial-contract.py')
C=importlib.util.module_from_spec(_spec);sys.modules[_spec.name]=C;_spec.loader.exec_module(C)
MAX_FIXTURE=1024*1024
PURPOSE='genuine-coordinated-financial-pre-v3-v1'
ARTIFACT_PARENT=pathlib.Path('/ci-fixture/full-parent')
FIXTURE_FILE='coordinated-financial-pre-v3-fixture-v1.json'
_HANDOFF_NAMES={'session_commands_file':'coordinated-fixture-session-commands.json',
 'delivery_choices_file':'coordinated-fixture-delivery-choices.json',
 'wallet_setup_file':'coordinated-fixture-wallet-setup.json',
 'host_password_file':'coordinated-fixture-host-password.private',
 'source_password_file':'coordinated-fixture-source-password.private'}
_KEYS=frozenset('''version purpose profile workspace financial fixed_identity delivery_choices sources witness
wallet_setup_json session_commands_file delivery_choices_file wallet_setup_file host_password_file
source_password_file original_fixture_expires_at_ms prepared_v3 admitted_v3 signed dispatch_requested
full_product_verified'''.split())
_SOURCE_KEYS=frozenset('''role reopen_selector entry_selection entry_selection_file original_capture
continuation_output_file result_output_file'''.split())
_TOKEN=object()
_SYNTHETIC_PASSWORDS={'host':b'synthetic-recovery-review-password',
                    'source':b'PUBLIC-NEVER-FUNDED-BORN-ROSTER-QUALIFICATION'}

def absolute(value):
    C.require(type(value) is str and 0<len(value)<=4096 and value.startswith('/') and
              not any(ord(x)<32 or ord(x)==127 for x in value) and
              '..' not in pathlib.PurePosixPath(value).parts,'fixture_path')
    return pathlib.Path(value)

def private_bytes(path,limit):
    path=absolute(str(path));fd=None
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        meta=os.fstat(fd)
        C.require(stat.S_ISREG(meta.st_mode) and meta.st_uid==os.getuid() and meta.st_nlink==1 and
                  stat.S_IMODE(meta.st_mode)==0o600 and 0<meta.st_size<=limit,'fixture_path')
        data=bytearray()
        while len(data)<=limit:
            block=os.read(fd,min(65536,limit+1-len(data)))
            if not block:break
            data.extend(block)
        C.require(len(data)==meta.st_size,'fixture_path')
        return data
    except OSError:
        raise C.Rejected('fixture_path') from None
    finally:
        if fd is not None:os.close(fd)

class SyntheticSecret:
    """Only the two fixed never-funded fixture passwords; never user credentials."""
    __slots__=('_bytes','_used')
    def __init__(self,token,value):
        C.require(token is _TOKEN and bytes(value) in _SYNTHETIC_PASSWORDS.values(),'fixture_secret')
        self._bytes=bytearray(value);self._used=False
    def __repr__(self):return '<SyntheticSecret redacted>'
    def consume(self,consumer):
        C.require(not self._used,'fixture_secret');self._used=True
        try:return consumer(memoryview(self._bytes).toreadonly())
        finally:
            for i in range(len(self._bytes)):self._bytes[i]=0
    def wipe(self):
        self._used=True
        for i in range(len(self._bytes)):self._bytes[i]=0

class Fixture:
    __slots__=('_data','deadline_ns','original_deadline_ns','_wall_start','_last_wall','_fixture_root','_artifact_root_identity')
    def __init__(self,data,original_deadline_ns,now_ns,wall_ms,expected_profile=C.PROFILE):
        C.require(expected_profile in (C.PROFILE,C.EXTERNAL_PROFILE,C.SEMANTIC_PROFILE))
        live=expected_profile in (C.EXTERNAL_PROFILE,C.SEMANTIC_PROFILE)
        C.exact(data,_KEYS,'fixture')
        C.require(data['version']==1 and data['purpose']==('genuine-coordinated-financial-live-pre-v3-v1' if live else PURPOSE),'fixture')
        C.require(all(data[k] is False for k in ('prepared_v3','admitted_v3','signed','dispatch_requested','full_product_verified')),'fixture')
        C.require(C.integer(original_deadline_ns,now_ns+1) and original_deadline_ns-now_ns<=C.ORIGINAL_NS,'fixture_deadline')
        expires=data['original_fixture_expires_at_ms']
        C.require(C.integer(expires,wall_ms+1) and expires-wall_ms<=900000,'fixture_deadline')
        self.deadline_ns=min(original_deadline_ns,now_ns+(expires-wall_ms)*1_000_000)
        self.original_deadline_ns=original_deadline_ns
        self._wall_start=self._last_wall=wall_ms
        for key in ('profile','workspace','financial','session_commands_file','delivery_choices_file','wallet_setup_file','host_password_file','source_password_file'):
            absolute(data[key])
        C.require(type(data['sources']) is list and len(data['sources'])==2,'fixture')
        accounts=set()
        for index,source in enumerate(data['sources'],1):
            C.exact(source,_SOURCE_KEYS,'fixture');C.require(source['role']=='signer'+str(index),'fixture')
            for key in ('entry_selection_file','continuation_output_file','result_output_file'):absolute(source[key])
            for key in ('continuation_output_file','result_output_file'):
                C.require(not os.path.lexists(source[key]),'fixture')
            selection=source['entry_selection'];C.require(type(selection) is dict,'fixture')
            account=selection.get('account_id');C.require(type(account) is str and len(account)==64 and account not in accounts,'fixture')
            accounts.add(account)
            C.require(source['reopen_selector']['account_id']==account and source['reopen_selector']['version']==2,'fixture')
            C.require(type(source['reopen_selector']['owner_setup_json']) is str,'fixture')
        witness=data['witness']
        C.require(type(witness) is dict and witness.get('purpose')==('coordinated-pre-v3-live-originals-v1' if live else 'coordinated-pre-v3-originals-v1') and
                  witness.get('version')==1 and len(witness.get('accounts',[]))==3,'fixture')
        C.require(accounts.issubset({a['account_id'] for a in witness['accounts']}),'fixture')
        C.require(type(data['wallet_setup_json']) is str and 0<len(data['wallet_setup_json'])<=32768,'fixture')
        self._data=data;self._fixture_root=None;self._artifact_root_identity=None
    def __repr__(self):return '<Fixture private original metadata>'
    @classmethod
    def load(cls,path,original_deadline_ns,expected_profile=C.PROFILE):
        selected=absolute(str(path));root=selected.parent
        C.require(selected.name==FIXTURE_FILE and root.parent==ARTIFACT_PARENT and
                  root.name.startswith('f-') and len(root.name)>2,'fixture_path')
        try:
            C.require(root.resolve(strict=True)==root,'fixture_path')
            for parent in (root,*root.parents):
                C.require(not stat.S_ISLNK(os.lstat(parent).st_mode),'fixture_path')
            before=os.stat(root,follow_symlinks=False)
            C.require(stat.S_ISDIR(before.st_mode) and before.st_uid==os.getuid() and
                      stat.S_IMODE(before.st_mode)==0o700,'fixture_path')
        except OSError:
            raise C.Rejected('fixture_path') from None
        raw=private_bytes(selected,MAX_FIXTURE)
        try:data=C.loads(raw,MAX_FIXTURE)
        finally:
            for i in range(len(raw)):raw[i]=0
        fixture=cls(data,original_deadline_ns,time.monotonic_ns(),time.time_ns()//1_000_000,expected_profile)
        fixture._fixture_root=root # independently selected original handoff
        fixture._artifact_root_identity=(before.st_dev,before.st_ino)
        fd=fixture._artifact_root_fd();os.close(fd)
        return fixture
    def check(self):
        now=time.monotonic_ns();wall=time.time_ns()//1_000_000
        C.require(now<self.deadline_ns and self._last_wall<=wall<self._data['original_fixture_expires_at_ms'],'fixture_deadline')
        self._last_wall=wall
    def source(self,owner):
        C.require(owner in ('Signer1','Signer2'),'fixture')
        return self._data['sources'][int(owner[-1])-1]
    def secret(self,purpose):
        self.check();C.require(purpose in _SYNTHETIC_PASSWORDS,'fixture_secret')
        raw=private_bytes(self._data[purpose+'_password_file'],256)
        try:
            C.require(bytes(raw)==_SYNTHETIC_PASSWORDS[purpose],'fixture_secret')
            return SyntheticSecret(_TOKEN,raw)
        finally:
            for i in range(len(raw)):raw[i]=0
    def validate_host_startup(self):
        """Closed synthetic PREPARE enrollment selection, never a native grant."""
        self.check()
        try:
            C.require(self._data['purpose'] in (PURPOSE,'genuine-coordinated-financial-live-pre-v3-v1'),'fixture')
            agreement=self._data['fixed_identity']['agreement_id']
            C.require(type(agreement) is str and bool(agreement),'fixture')
            C.require(len(self._data['sources'])==2,'fixture')
            for index,source in enumerate(self._data['sources'],1):
                C.require(source['role']=='signer'+str(index),'fixture')
                scope=source['original_capture']['scope']
                C.require(scope['proposal']['manifest']['agreement']['agreement_id']==agreement,'fixture')
                for role in ('constructor','prover'):
                    C.require(scope[role]['principal_id']=='synthetic-roster-host','fixture')
        except (KeyError,TypeError,AttributeError):
            raise C.Rejected('fixture') from None

    def reviewer_selection_path(self,owner):
        """One fresh inert Host selection artifact; not an approval or result."""
        self.check();source=self.source(owner);index=int(owner[-1])
        def identifier(value):
            return type(value) is str and 0<len(value)<=128 and all(
                c.isascii() and (c.isalnum() or c in '-_.:') for c in value)
        account=source['entry_selection']['account_id']
        scope=source['original_capture']['scope'];participant=scope['participant_id']
        C.require(type(account) is str and len(account)==64 and
                  all(c in '0123456789abcdef' for c in account) and identifier(participant),'fixture')
        C.require(scope['account_id']==account and source['reopen_selector']['account_id']==account,'fixture')
        other=self.source('Signer2' if owner=='Signer1' else 'Signer1')
        C.require(other['entry_selection']['account_id']!=account and
                  other['original_capture']['scope']['participant_id']!=participant,'fixture')
        choices=self._data['delivery_choices']
        C.exact(choices,('submission_operation_id','provider','route','minimum_expiry_margin_blocks',
                        'maximum_fresh_admission_lifetime_ms','maximum_explicitly_approved_attempts'),'fixture')
        provider=choices['provider'];C.exact(provider,('source_id','endpoint','trust_profile'),'fixture')
        C.require(identifier(choices['submission_operation_id']) and len(choices['submission_operation_id'])>=16 and
                  identifier(provider['source_id']) and type(provider['endpoint']) is str and
                  provider['endpoint'].startswith('https://') and len(provider['endpoint'])<=2048 and
                  provider['trust_profile']=='single_tls_provider_report_not_consensus','fixture')
        route=choices['route'];C.require(type(route) is dict,'fixture')
        if route.get('kind')=='direct':C.exact(route,('kind',),'fixture')
        else:
            C.exact(route,('kind','origin'),'fixture')
            C.require(route['kind']=='existing_http_connect' and type(route['origin']) is str and
                      route['origin'].startswith('http://') and len(route['origin'])<=2048,'fixture')
        C.require(C.integer(choices['minimum_expiry_margin_blocks'],1,100) and
                  C.integer(choices['maximum_fresh_admission_lifetime_ms'],1,120000) and
                  C.integer(choices['maximum_explicitly_approved_attempts'],1,128),'fixture')
        value={'import_operation_id':f'full-native-import-{index}',
               'redisclosure_operation_id':f'full-native-redisclose-{index}',
               'account_id':account,'participant_id':participant,'choices':choices}
        original=source['original_capture']['request']['operation_id']
        C.require(original not in (value['import_operation_id'],value['redisclosure_operation_id']),'fixture')
        data=json.dumps(value,separators=(',',':')).encode('ascii')
        C.require(0<len(data)<=262144,'fixture')
        fd=self._artifact_root_fd();created=None
        try:
            protected=absolute(self._data['profile'])
            C.require(protected.resolve(strict=True)==protected,'fixture_path')
            protected_meta=os.stat(protected,follow_symlinks=False)
            C.require(stat.S_ISDIR(protected_meta.st_mode),'fixture_path')
            for parent in (self._fixture_root,*self._fixture_root.parents):
                meta=os.stat(parent,follow_symlinks=False)
                C.require((meta.st_dev,meta.st_ino)!=(protected_meta.st_dev,protected_meta.st_ino),'fixture_path')
            C.require(not self._fixture_root.is_relative_to(protected),'fixture_path')
            # Bind the preserved ordinary choices/entry data to their actual
            # authoritative handoff files before creating a new selection.
            for key,expected in (('delivery_choices_file',choices),):
                raw=private_bytes(self._data[key],262144)
                try:C.require(C.loads(raw,262144)==expected,'fixture')
                finally:
                    for n in range(len(raw)):raw[n]=0
            entry=absolute(source['entry_selection_file'])
            C.require(entry.parent==absolute(self._data['session_commands_file']).parent and
                      entry.name==f'coordinated-fixture-source-{index}-entry.json','fixture_path')
            raw=private_bytes(entry,262144)
            try:C.require(C.loads(raw,262144)==source['entry_selection'],'fixture')
            finally:
                for n in range(len(raw)):raw[n]=0
            name=f'coordinated-reviewer-selection-{index}.json'
            created=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
            meta=os.fstat(created)
            C.require(stat.S_ISREG(meta.st_mode) and meta.st_uid==os.getuid() and
                      meta.st_nlink==1 and stat.S_IMODE(meta.st_mode)==0o600,'fixture_path')
            offset=0
            while offset<len(data):
                count=os.write(created,data[offset:]);C.require(count>0,'fixture_path');offset+=count
            os.fsync(created)
            path=absolute(self._data['session_commands_file']).parent/name
            current=path.stat(follow_symlinks=False)
            C.require((current.st_dev,current.st_ino)==(meta.st_dev,meta.st_ino) and current.st_size==len(data) and
                      stat.S_ISREG(current.st_mode) and current.st_uid==os.getuid() and
                      current.st_nlink==1 and stat.S_IMODE(current.st_mode)==0o600,'fixture_path')
            verify=self._artifact_root_fd()
            try:C.require((os.fstat(verify).st_dev,os.fstat(verify).st_ino)==(os.fstat(fd).st_dev,os.fstat(fd).st_ino),'fixture_path')
            finally:os.close(verify)
            return str(path)
        except OSError:raise C.Rejected('fixture_path') from None
        finally:
            if created is not None:os.close(created)
            os.close(fd)


    def _artifact_root_fd(self):
        """Pin the native parent's owned child root, not a self-declared folder.

        Fixture.load binds the selected handoff path; native hold_ready_fixture
        obtains that path from child.temporary_root(). Cleanup owns that same
        f-* directory. Metadata checks never read any secret/token contents.
        Caller owns the returned fd and must close it.
        """
        fd=None
        try:
            root=self._fixture_root
            C.require(type(root) is pathlib.PosixPath and root.parent==ARTIFACT_PARENT and
                      root.name.startswith('f-') and len(root.name)>2,'fixture_path')
            C.require(root.resolve(strict=True)==root,'fixture_path')
            for parent in (root,*root.parents):
                C.require(not stat.S_ISLNK(os.lstat(parent).st_mode),'fixture_path')
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            meta=os.fstat(fd);observed=os.lstat(root);identity=(meta.st_dev,meta.st_ino)
            C.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid==os.getuid() and
                      stat.S_IMODE(meta.st_mode)==0o700 and
                      identity==(observed.st_dev,observed.st_ino),'fixture_path')
            C.require(self._artifact_root_identity in (None,identity),'fixture_path')
            for key,name in _HANDOFF_NAMES.items():
                C.require(self._data[key]==str(root/name),'fixture_path')
                item=os.stat(name,dir_fd=fd,follow_symlinks=False)
                C.require(stat.S_ISREG(item.st_mode) and item.st_uid==os.getuid() and
                          item.st_nlink==1 and stat.S_IMODE(item.st_mode)==0o600 and
                          0<item.st_size<=65536,'fixture_path')
            self._artifact_root_identity=identity
            result=fd;fd=None;return result
        except (OSError,KeyError,TypeError,ValueError,RuntimeError):
            raise C.Rejected('fixture_path') from None
        finally:
            if fd is not None:os.close(fd)

    def host_credential_destination(self):
        """Return an absent path; native enroll alone creates the token.

        Never precreate/read/overwrite/delete/reuse it. Native external_destination
        and write_new remain final race guards after this inert path check.
        """
        self.validate_host_startup();fd=None
        try:
            fd=self._artifact_root_fd();root=self._fixture_root
            profile=absolute(self._data['profile'])
            C.require(profile.resolve(strict=True)==profile,'fixture_path')
            profile_meta=os.stat(profile,follow_symlinks=False)
            C.require(stat.S_ISDIR(profile_meta.st_mode),'fixture_path')
            for parent in (root,*root.parents):
                meta=os.stat(parent,follow_symlinks=False)
                C.require((meta.st_dev,meta.st_ino)!=(profile_meta.st_dev,profile_meta.st_ino),'fixture_path')
            name='coordinated-host-runtime-session.token';destination=root/name
            C.require(not destination.is_relative_to(profile),'fixture_path')
            try:os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise C.Rejected('fixture_path')
            return str(destination)
        except (OSError,KeyError,TypeError,ValueError,RuntimeError):
            raise C.Rejected('fixture_path') from None
        finally:
            if fd is not None:os.close(fd)

    def host_startup_value(self,name):
        self.validate_host_startup()
        if name in ('profile','workspace','session_commands_file'):return self.top_path(name)
        if name=='credential':return self.host_credential_destination()
        # Native export requires Read+Coordinate+Disclose. The existing PREPARE
        # choice also includes Propose+Intent; genuine session approval remains required.
        values={'principal':'synthetic-roster-host','scope':'OWNED','shared':'',
                'mode':'PREPARE','origin':''}
        C.require(name in values,'fixture')
        return values[name]

    def top_path(self,name):
        C.require(name in ('profile','workspace','financial','session_commands_file','delivery_choices_file','wallet_setup_file'),'fixture')
        return self._data[name]
    def source_path(self,owner,name,*,must_exist=False):
        C.require(name in ('entry_selection_file','continuation_output_file','result_output_file'),'fixture')
        path=self.source(owner)[name]
        if must_exist:
            raw=private_bytes(path,65536)
            for i in range(len(raw)):raw[i]=0
        return path
    def form(self,owner,kind):
        self.check();source=self.source(owner)
        if kind=='v3':return {'V3Selection':json.dumps(source['entry_selection'],separators=(',',':'))}
        if kind=='owner':return {'OwnerConfiguration':source['reopen_selector']['owner_setup_json']}
        if kind=='financial':
            writer=C.loads(source['reopen_selector']['owner_setup_json'],16384)
            paths=self._data['witness']['writer_client']
            writer['client_certificate_der']=paths['certificate_der'];writer['client_private_key_pkcs8_der']=paths['private_key_pkcs8_der']
            writer['trusted_server_root_der']=paths['trusted_server_root_der']
            return {'WriterConfiguration':json.dumps(writer,separators=(',',':')),'WalletConfiguration':self._data['wallet_setup_json']}
        C.require(kind=='witness','fixture')
        form=dict(self._data['witness']['form']);form['expected_account_id']=source['entry_selection']['account_id']
        names={'endpoint':'Endpoint','server_name':'ServerName','witness_id':'WitnessId',
               'pinned_server_certificate_digest':'PinnedServerCertificate','network_profile_id':'NetworkProfile',
               'expected_account_id':'AccountId','owner_certificate_der_hex':'OwnerCertificateDerHex',
               'storage_key_file':'StorageKey','server_certificate_der':'ServerCertificate',
               'server_private_key_pkcs8_der':'ServerPrivateKey','trusted_client_root_der':'TrustedClientRoot'}
        C.require(set(form)==set(names),'fixture')
        return {names[k]:v for k,v in form.items()}
    def preflight_input_budget(self):
        # Fixed full-flow bound, computed before input from actual public fields.
        lengths=sum(len(value) for owner in ('Signer1','Signer2') for kind in ('v3','owner','financial','witness') for value in self.form(owner,kind).values())
        # Worst-case US keyboard shift/down/up plus rendering progress commands.
        cost=lengths*4+32768
        C.input_budget(cost<=C.MAX_NATIVE_COMMANDS,'fixture_preflight',cost)
        return cost
