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
    __slots__=('_data','deadline_ns','original_deadline_ns','_wall_start','_last_wall')
    def __init__(self,data,original_deadline_ns,now_ns,wall_ms,expected_profile=C.PROFILE):
        C.require(expected_profile in (C.PROFILE,C.EXTERNAL_PROFILE))
        live=expected_profile==C.EXTERNAL_PROFILE
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
        self._data=data
    def __repr__(self):return '<Fixture private original metadata>'
    @classmethod
    def load(cls,path,original_deadline_ns,expected_profile=C.PROFILE):
        raw=private_bytes(path,MAX_FIXTURE)
        try:data=C.loads(raw,MAX_FIXTURE)
        finally:
            for i in range(len(raw)):raw[i]=0
        return cls(data,original_deadline_ns,time.monotonic_ns(),time.time_ns()//1_000_000,expected_profile)
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
        C.require(cost<=C.MAX_NATIVE_COMMANDS,'input_budget')
        return cost
